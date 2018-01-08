# -*- coding: utf-8 -*-

import json
import base64
from time import mktime
from datetime import datetime

import nacl.hash
import nacl.pwhash
import nacl.encoding

import tornado.gen
import tornado.web

from .base import BaseHandler


class WebAuthHandler(BaseHandler):
    def get_current_user(self):
        return


class TokenAuthHandler(BaseHandler):
    """ Token based authentication for handlers """

    @tornado.gen.coroutine
    def prepare(self):
        now = mktime(datetime.now().utctimetuple())
        access_token = self.get_argument('access_token')

        tokens_dct = json.loads(base64.decodebytes(access_token).decode())
        verifier_hash = nacl.hash.blake2b(tokens_dct['verifier'].encode(),
                                          key=self.hmac_key,
                                          encoder=nacl.encoding.HexEncoder)

        query = {
            'access_tokens.selector': {'$eq': tokens_dct['selector']},
            'access_tokens.verifier': {'$eq': verifier_hash},
            'access_tokens.expires_in': {'$lte': now}
        }
        user_dct = yield self.db.users.find_one(query)

        if user_dct is not None:
            self.current_user = {
                'username': user_dct['username'],
                'access_token': access_token
            }
        else:
            self.current_user = None


class SignupHandler(BaseHandler):

    @tornado.gen.coroutine
    def post(self):

        username = self.get_argument('username')
        password = self.get_argument('password')

        # Check does user already have account
        user_dct = yield self.db.users.find_one({'username': username})
        if user_dct is None:
            self.set_status(403)
            self.finish()
            return

        # TODO: save user's public key for signature checking

        password_hash = yield self.executor.submit(
            nacl.pwhash.str,
            tornado.escape.utf8(password)
        )

        user_dct = {'username': username, 'password_hash': password_hash}
        yield self.db.users.insert(user_dct)
        self.set_status(200)
