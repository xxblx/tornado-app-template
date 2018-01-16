# -*- coding: utf-8 -*-

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

        try:
            select_token = self.get_argument('select_token')
            verify_token = self.get_argument('verify_token')
        except tornado.web.MissingArgumentError:
            self.current_user = None
            self.set_status(400)
            self.finish()
            return

        # Get user's data from db
        user_dct = yield self.db.users.aggregate([
            {'$match': {
                'access_tokens.select_token': {'$eq': select_token}
            }},
            {'$unwind': '$access_tokens'},
            {'$match': {
                'access_tokens.select_token': {'$eq': select_token}
            }},
            {'$project': {
                'username': 1,
                'pubkey_hex': 1,
                'verify_token': '$access_tokens.verify_token',
                'expires_in': '$access_tokens.expires_in'
            }}
        ]).to_list(1)

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
            verify_token = pubkey.verify(
                base64.decodebytes(tornado.escape.utf8(verify_token))
            )
        except nacl.exceptions.BadSignatureError:
            self.current_user = None
            return

        # Verifier's hash check
        verify_hash = nacl.hash.blake2b(verify_token, key=self.hmac_key,
                                        encoder=nacl.encoding.HexEncoder)

        if not compare_digest(verify_hash, user_dct['verify_token']):
            self.current_user = None
            return

        self.current_user = {
            'username': user_dct['username'],
            'select_token': select_token
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
            self.set_status(400)
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
