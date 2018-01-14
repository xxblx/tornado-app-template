# -*- coding: utf-8 -*-

import json
import base64
from time import mktime
from datetime import datetime
from hmac import compare_digest

import nacl.hash
import nacl.pwhash
import nacl.signing
import nacl.encoding
import nacl.exceptions

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

        if not self.get_arguments('access_token'):
            self.current_user = None
            return

        access_token = self.get_argument('access_token')

        tokens_dct = json.loads(
            base64.decodebytes(tornado.escape.utf8(access_token)).decode()
        )

        # Get user's data from db
        user_dct = yield self.db.users.aggregate([
            {'$match': {
                'access_tokens.selector': {'$eq': tokens_dct['selector']}
            }},
            {'$unwind': '$access_tokens'},
            {'$match': {
                'access_tokens.selector': {'$eq': tokens_dct['selector']}
            }},
            {'$project': {
                'username': 1,
                'pubkey_hex': 1,
                'verifier': '$access_tokens.verifier',
                'expires_in': '$access_tokens.expires_in'
            }}
        ]).to_list()

        # Selector not found
        if not user_dct:
            self.current_user = None
            return
        else:
            user_dct = user_dct[0]

        # Time check
        if now > user_dct['expires_in']:
            self.current_user = None
            return

        # Signature check
        pubkey = nacl.signing.VerifyKey(user_dct['pubkey_hex'],
                                        encoder=nacl.encoding.HexEncoder)
        try:
            verifier = pubkey.verify(tokens_dct['verifier'].encode())
        except nacl.exceptions.BadSignatureError:
            self.current_user = None
            return

        # Verifier's hash check
        verifier_hash = nacl.hash.blake2b(verifier,
                                          key=self.hmac_key,
                                          encoder=nacl.encoding.HexEncoder)

        if not compare_digest(verifier_hash, user_dct['verifier']):
            self.current_user = None
            return

        self.current_user = {
            'username': user_dct['username'],
            'access_token': access_token
        }


class SignupHandler(BaseHandler):

    @tornado.gen.coroutine
    def post(self):

        username = self.get_argument('username')
        password = self.get_argument('password')
        pubkey_hex = self.get_argument('pubkey_hex')

        # Check does user already have account
        user_dct = yield self.db.users.find_one({'username': username})
        if user_dct is not None:
            self.set_status(403)
            self.finish()
            return

        password_hash = yield self.executor.submit(
            nacl.pwhash.str,
            tornado.escape.utf8(password)
        )

        user_dct = {
            'username': username,
            'password_hash': password_hash,
            'pubkey_hex': tornado.escape.utf8(pubkey_hex)
        }
        yield self.db.users.insert(user_dct)
        self.set_status(200)
