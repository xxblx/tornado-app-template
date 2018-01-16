# -*- coding: utf-8 -*-

from uuid import uuid4
from time import mktime
from hmac import compare_digest
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
        select_token = uuid4().hex
        verify_token = uuid4().hex
        refresh_token = uuid4().hex
        verify_token_hash = nacl.hash.blake2b(verify_token.encode(),
                                              key=self.hmac_key,
                                              encoder=nacl.encoding.HexEncoder)
        expires_in = datetime.now() + timedelta(hours=2)
        expires_in = mktime(expires_in.utctimetuple())

        # Store token in db
        tokens_dct = {
            'select_token': select_token,
            'verify_token': verify_token_hash,
            'refresh_token': refresh_token,
            'expires_in': expires_in,
        }
        yield self.db.users.update({'username': username},
                                   {'$push': {'access_tokens': tokens_dct}})

        # Send to user verify token as is
        tokens_dct['verify_token'] = verify_token
        return tokens_dct


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

        # Password verify
        try:
            yield self.executor.submit(
                nacl.pwhash.verify,
                user_dct['password_hash'],
                tornado.escape.utf8(password)
            )
        except nacl.exceptions.InvalidkeyError:
            self.set_status(403)
            self.finish()
            return

        user_tokens = yield self.generate_token(username)
        self.write(user_tokens)


class TokenRenewHandler(TokenBaseHandler):

    @tornado.gen.coroutine
    def post(self):
        select_token = self.get_argument('select_token')
        verify_token = self.get_argument('verify_token')
        refresh_token = self.get_argument('refresh_token')

        # Looking for tokens in db
        user_dct = yield self.db.users.aggregate([
            {'$match': {
                'access_tokens.select_token': {'$eq': select_token},
                'access_tokens.refresh_token': {'$eq': refresh_token}
            }},
            {'$unwind': '$access_tokens'},
            {'$match': {
                'access_tokens.select_token': {'$eq': select_token},
                'access_tokens.refresh_token': {'$eq': refresh_token}
            }},
            {'$project': {
                'username': 1,
                'verify_token': '$access_tokens.verify_token',
            }}
        ]).to_list(1)

        if not user_dct:
            self.set_status(403)
            self.finish()
            return
        else:
            user_dct = user_dct[0]

        # TODO: sign check
        verify_hash = nacl.hash.blake2b(tornado.escape.utf8(verify_token),
                                        key=self.hmac_key,
                                        encoder=nacl.encoding.HexEncoder)

        # Verifier's hash check
        if not compare_digest(verify_hash, user_dct['verify_token']):
            self.set_status(403)
            self.finish()
            return

        user_tokens = yield self.generate_token(user_dct['username'])
        # TODO: remove old tokens from db
        self.write(user_tokens)
