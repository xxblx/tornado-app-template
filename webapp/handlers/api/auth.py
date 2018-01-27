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

from ..base import BaseHandler


class TokenAuthHandler(BaseHandler):
    """ Token based authentication for handlers """

    @tornado.gen.coroutine
    def prepare(self):
        self.current_user = None
        now = mktime(datetime.now().utctimetuple())

        try:
            select_token = self.get_argument('select_token')
            verify_token = self.get_argument('verify_token')
        except tornado.web.MissingArgumentError:
            raise tornado.web.HTTPError(403, 'invalid tokens')

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
            raise tornado.web.HTTPError(403, 'invalid select token')
        else:
            user_dct = user_dct[0]

        # Time check
        if now > user_dct['expires_in']:
            raise tornado.web.HTTPError(403, 'expired tokens')

        # Signature check
        pubkey = nacl.signing.VerifyKey(user_dct['pubkey_hex'],
                                        encoder=nacl.encoding.HexEncoder)
        try:
            verify_token = pubkey.verify(
                base64.decodebytes(tornado.escape.utf8(verify_token))
            )
        except nacl.exceptions.BadSignatureError:
            raise tornado.web.HTTPError(403, 'invalid signature')

        # Verifier's hash check
        verify_hash = nacl.hash.blake2b(verify_token, key=self.hmac_key,
                                        encoder=nacl.encoding.HexEncoder)

        if not compare_digest(verify_hash, user_dct['verify_token']):
            raise tornado.web.HTTPError(403, 'invalid verify token')

        self.current_user = {
            'username': user_dct['username'],
            'select_token': select_token
        }


class SignupHandler(BaseHandler):

    @tornado.gen.coroutine
    def post(self):
        username = self.get_argument('username')
        password = self.get_argument('password')

        privkey = self.get_argument('privkey')
        pubkey_hex = self.get_argument('pubkey_hex')

        privkey_salt = self.get_argument('privkey_salt')
        privkey_opslimit = self.get_argument('privkey_opslimit')
        privkey_memlimit = self.get_argument('privkey_memlimit')

        # Check does user already have account
        user_dct = yield self.db.users.find_one({'username': username})
        if user_dct is not None:
            raise tornado.web.HTTPError(400)

        password_hash = yield self.executor.submit(
            nacl.pwhash.str,
            tornado.escape.utf8(password)
        )

        user_dct = {
            'username': username,
            'password_hash': password_hash,
            'privkey': tornado.escape.utf8(privkey),
            'pubkey_hex': tornado.escape.utf8(pubkey_hex),
            'privkey_salt': tornado.escape.utf8(privkey_salt),
            'privkey_opslimit': privkey_opslimit,
            'privkey_memlimit': privkey_memlimit
        }
        yield self.db.users.insert(user_dct)


class GetKeyHandler(BaseHandler):

    @tornado.gen.coroutine
    def post(self):
        username = self.get_argument('username')
        password = self.get_argument('password')

        user_dct = yield self.db.users.find_one({'username': username})
        if user_dct is None:
            raise tornado.web.HTTPError(403, 'invalid username')

        # Password verify
        try:
            yield self.executor.submit(
                nacl.pwhash.verify,
                user_dct['password_hash'],
                tornado.escape.utf8(password)
            )
        except nacl.exceptions.InvalidkeyError:
            raise tornado.web.HTTPError(403, 'invalid password')

        self.write({'privkey': user_dct['privkey']})
