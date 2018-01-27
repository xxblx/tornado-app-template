# -*- coding: utf-8 -*-

import os.path
from concurrent.futures import ThreadPoolExecutor

import nacl.utils
import tornado.web
from motor import MotorClient

from .handlers.testweb import TestWebHandler
from .handlers.auth import LoginHandler, LogoutHandler

from .handlers.api.testapi import TestApiHandler
from .handlers.api.auth import SignupHandler, GetKeyHandler
from .handlers.api.tokens import TokenGetHandler, TokenRenewHandler

from .conf import (DBHOST, DBNAME, WORKERS, DEBUG, TOKEN_EXPIRES_TIME)


class WebApp(tornado.web.Application):

    def __init__(self):
        handlers = [
            (r'/', TestWebHandler),
            (r'/login', LoginHandler),
            (r'/logout', LogoutHandler),
            (r'/api/signup', SignupHandler),
            (r'/api/token/get', TokenGetHandler),
            (r'/api/token/renew', TokenRenewHandler),
            (r'/api/key/get', GetKeyHandler),
            (r'/api/test', TestApiHandler)
        ]

        template_path = os.path.join(os.path.dirname(__file__), 'templates')
        settings = {
            'template_path': template_path,
            'login_url': '/login',
            'debug': DEBUG,
            'xsrf_cookies': True,
            'cookie_secret': nacl.utils.random(size=64)
        }

        super(WebApp, self).__init__(handlers, **settings)

        self.token_expires_time = TOKEN_EXPIRES_TIME

        # MongoDB
        self.db = MotorClient(**DBHOST)[DBNAME]

        # ThreadPoolExecutor for long tasks like password hashing
        self.executor = ThreadPoolExecutor(WORKERS)

        # Secret key for HMAC
        self.hmac_key = nacl.utils.random(size=64)
