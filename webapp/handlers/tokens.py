# -*- coding: utf-8 -*-

import json
import base64
from uuid import uuid4
from time import mktime
from datetime import datetime, timedelta

import nacl.hash
import nacl.pwhash
import nacl.encoding

import tornado.gen

from .base import BaseHandler


class TokenBaseHandler(BaseHandler):

    @tornado.gen.coroutine
    def generate_token(self, username):
        """ Generate access token and refresh token """

        # Token split in two parts: selector and verifier
        # Selector stores as is in db, but verifier stores as hash
        selector = uuid4().hex
        verifier = uuid4().hex
        verifier_hash = nacl.hash.blake2b(verifier.encode(), key=self.hmac_key,
                                          encoder=nacl.encoding.HexEncoder)
        expires_in = datetime.now() + timedelta(hours=2)
        expires_in = mktime(expires_in.utctimetuple())

        tokens_dct = {'selector': selector, 'verifier': verifier}
        access_token = base64.encodebytes(json.dumps(tokens_dct).encode())
        refresh_token = uuid4().hex

        # Store token in db
        tokens_dct_db = {
            'selector': selector,
            'verifier': verifier_hash,
            'refresh': refresh_token,
            'expires_in': expires_in,
        }
        yield self.db.users.update({'username': username},
                                   {'$push': {'access_tokens': tokens_dct_db}})

        user_tokens = {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'expires_in': expires_in
        }

        return user_tokens


class TokenGetHandler(TokenBaseHandler):

    @tornado.gen.coroutine
    def post(self):
        username = self.get_argument('username')
        password = self.get_argument('password')

        user_dct = yield self.db.users.find_one({'username': username})
        if user_dct is None:
            self.set_status(403)
            self.finish()
            return

        password_check = yield self.executor.submit(
            nacl.pwhash.verify,
            user_dct['password_hash'],
            tornado.escape.utf8(password)
        )

        if not password_check:
            self.set_status(403)
            self.finish()
            return

        user_tokens = yield self.generate_token(username)
        self.write(**user_tokens)


class TokenRenewHandler(TokenBaseHandler):

    @tornado.gen.coroutine
    def post(self):
        access_token = self.get_argument('access_token')
        refresh_token = self.get_argument('refresh_token')

        tokens_dct = json.loads(base64.decodebytes(access_token).decode())
        verifier_hash = nacl.hash.blake2b(tokens_dct['verifier'].encode(),
                                          key=self.hmac_key,
                                          encoder=nacl.encoding.HexEncoder)

        # Looking for tokens in db
        query = {
            'access_tokens.refresh': {'$eq': refresh_token},
            'access_tokens.selector': {'$eq': tokens_dct['selector']},
            'access_tokens.verifier': {'$eq': verifier_hash},
        }
        user_dct = yield self.db.users.find_one(query)

        if user_dct is None:
            self.set_status(403)
            self.finish()
            return

        user_tokens = yield self.generate_token(user_dct['username'])
        self.write(**user_tokens)
