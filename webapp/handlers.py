# -*- coding: utf-8 -*-

import json
import base64
from uuid import uuid4
from time import mktime
from datetime import datetime, timedelta

import nacl.hash
import nacl.pwhash
import nacl.encoding

import tornado.web
import tornado.gen
import tornado.escape
from tornado.concurrent import run_on_executor


class BaseHandler(tornado.web.RequestHandler):

    @property
    def db(self):
        return self.application.db

    @property
    def executor(self):
        return self.application.executor

    @property
    def hmac_key(self):
        return self.application.hmac_key


class SignupHandler(BaseHandler):

    @tornado.gen.coroutine
    def post(self):

        username = self.get_argument('username')
        password = self.get_argument('password')

        # TODO: save user's public key for signature checking
        # TODO: check - does user already have account?

        password_hash = yield self.executor.submit(
            nacl.pwhash.str,
            tornado.escape.utf8(password)
        )

        user_dct = {'username': username, 'password_hash': password_hash}
        yield self.db.users.insert(user_dct)
        self.set_status(200)


class TokenGetHandler(BaseHandler):

    @tornado.gen.coroutine
    def post(self):
        username = self.get_argument('username')
        password = self.get_argument('password')

        user_dct = yield self.db.users.find_one({'username': username})
        if user_dct is None:
            self.set_status(403)
            self.finish()

        password_check = yield self.executor.submit(
            nacl.pwhash.verify,
            user_dct['password_hash'],
            tornado.escape.utf8(password)
        )

        if not password_check:
            self.set_status(403)
            self.finish()

        # Token split in two parts: selector and verifier
        # Selector stores as is in db, but verifier stores as hash
        selector = uuid4().hex
        verifier = uuid4().hex
        verifier_hash = nacl.hash.blake2b(verifier, key=self.hmac_key,
                                          encoder=nacl.encoding.HexEncoder)
        expires_in = datetime.now() + timedelta(hours=2)
        expires_in = mktime(expires_in.utctimetuple())

        token_dct = {'selector': selector, 'verifier': verifier}
        access_token = base64.encodebytes(json.dumps(token_dct).encode())
        refresh_token = uuid4().hex

        # Store token in db
        token_dct_db = {
            'selector': selector,
            'verifier': verifier_hash,
            'refresh': refresh_token,
            'expires_in': expires_in,
        }
        yield self.db.users.update({'username': username},
                                   {'$push': {'access_tokens': token_dct_db}})

        self.write({
            'access_token': access_token,
            'refresh_token': refresh_token,
            'expires_in': expires_in
        })


class TokenRefreshHandler(BaseHandler):

    @tornado.gen.coroutine
    def post(self):
        pass
