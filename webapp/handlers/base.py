# -*- coding: utf-8 -*-

import nacl.pwhash
import nacl.exceptions

import tornado.web
import tornado.concurrent


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

    @tornado.concurrent.run_on_executor
    def verify_password(self, password_hash, password):
        """ Verify password hash with password """

        try:
            nacl.pwhash.verify(password_hash, password)
            result = True
        except nacl.exceptions.InvalidkeyError:
            result = False

        return result
