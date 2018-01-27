#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import base64
import logging
import os.path
from functools import wraps
from urllib.parse import urljoin, urlparse

import nacl.hash
import nacl.pwhash
import nacl.secret
import nacl.signing
import nacl.encoding

import requests

from webapp.conf import HOST, PORT


class AppClient:

    client_dir = os.path.dirname(os.path.realpath(__file__))
    host_url = 'http://%s:%d' % (HOST, PORT)

    username = 'testuser'
    password = 'testpassword'
    tokens = None
    __signing_key = None

    @property
    def signing_key(self):
        if self.__signing_key is not None:
            return self.__signing_key

        path = os.path.join(self.client_dir, 'signing_key')
        if os.path.exists(path):
            with open(path, 'rb') as f:
                key_bytes = f.read()
            self.__signing_key = nacl.signing.SigningKey(key_bytes)

        else:
            self.__signing_key = nacl.signing.SigningKey.generate()
            with open(path, 'wb') as f:
                f.write(self.__signing_key.encode())

        return self.__signing_key

    def __init__(self):
        self.logger = logging.getLogger('client')
        self.logger.setLevel(logging.DEBUG)

        stream = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(path)s - %(status_code)d - %(message)s'
        )
        stream.setFormatter(formatter)
        self.logger.addHandler(stream)

    def __request(method):
        @wraps(method)
        def wrapper(self, *args, **kwargs):
            r, data = method(self, *args, **kwargs)
            dct = {'status_code': r.status_code, 'path': urlparse(r.url).path}
            self.logger.debug(data, extra=dct)
            return r, data
        return wrapper

    @__request
    def signup_user(self):
        verify_key = self.signing_key.verify_key
        verify_key_hex = verify_key.encode(encoder=nacl.encoding.HexEncoder)

        # Encrypt signing key
        signing_key_bytes = self.signing_key.encode()
        password_hash = nacl.hash.blake2b(self.password.encode(),
                                          encoder=nacl.encoding.HexEncoder)

        salt = nacl.utils.random(nacl.pwhash.argon2i.SALTBYTES)
        ops = nacl.pwhash.argon2i.OPSLIMIT_SENSITIVE
        mem = nacl.pwhash.argon2i.MEMLIMIT_SENSITIVE
        key = nacl.pwhash.argon2i.kdf(nacl.secret.SecretBox.KEY_SIZE,
                                      password_hash, salt, opslimit=ops,
                                      memlimit=mem)

        box = nacl.secret.SecretBox(key)
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        encrypted_signing_key = box.encrypt(signing_key_bytes, nonce)

        encrypted_signing_key = base64.encodebytes(encrypted_signing_key)
        salt = base64.encodebytes(salt)

        # Send data to server
        data = {
            'username': self.username,
            'password': self.password,
            'privkey': encrypted_signing_key.decode(),
            'pubkey_hex': verify_key_hex.decode(),
            'privkey_salt': salt.decode(),
            'privkey_opslimit': ops,
            'privkey_memlimit': mem
        }

        url = urljoin(self.host_url, '/api/signup')
        r = requests.post(url, data=data)
        return r, data

    @__request
    def api_test(self, with_token=True):

        if with_token:
            verify_signed = self.signing_key.sign(
                self.tokens['verify_token'].encode()
            )
            data = {
                'select_token': self.tokens['select_token'],
                'verify_token': base64.encodebytes(verify_signed).decode()
            }
        else:
            data = None

        url = urljoin(self.host_url, '/api/test')
        r = requests.post(url, data=data)
        return r, data

    @__request
    def get_tokens(self, save_tokens=True):
        url = urljoin(self.host_url, '/api/token/get')
        data = {
            'username': self.username,
            'password': self.password
        }
        r = requests.post(url, data=data)
        if save_tokens:
            self.tokens = r.json()
        return r, data

    @__request
    def renew_token(self, save_tokens=True):
        url = urljoin(self.host_url, '/api/token/renew')
        verify_signed = self.signing_key.sign(
            self.tokens['verify_token'].encode()
        )
        data = {
            'select_token': self.tokens['select_token'],
            'verify_token': base64.encodebytes(verify_signed).decode(),
            'refresh_token': self.tokens['refresh_token']
        }

        r = requests.post(url, data=data)
        if save_tokens:
            self.tokens = r.json()
        return r, data

    def run(self, signup=True):

        # Register user
        self.signup_user()

        # Try access to /api/test without token
        self.api_test(with_token=False)

        # Get tokens
        self.get_tokens()

        # Test api access with token
        self.api_test()

        # Renew token
        time.sleep(2)
        self.renew_token()


if __name__ == '__main__':
    client = AppClient()
    client.run()
