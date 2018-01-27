# -*- coding: utf-8 -*-

import tornado.web

from .auth import WebAuthHandler


class TestWebHandler(WebAuthHandler):
    @tornado.web.authenticated
    def get(self):
        self.write('<p>Hello World!</p>')
