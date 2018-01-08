# -*- coding: utf-8 -*-

import tornado.web

from .base import BaseHandler
from .auth import TokenAuthHandler


class TestApiHandler(BaseHandler, TokenAuthHandler):
    @tornado.web.authenticated
    def post(self):
        self.write('ok')
