# -*- coding: utf-8 -*-

import tornado.web


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
