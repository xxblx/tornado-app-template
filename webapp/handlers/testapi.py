# -*- coding: utf-8 -*-

import tornado.web

from .auth import TokenAuthHandler


class TestApiHandler(TokenAuthHandler):
    @tornado.web.authenticated
    def post(self):
        self.set_status(200)
