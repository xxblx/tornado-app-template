# -*- coding: utf-8 -*-

from concurrent.futures import ThreadPoolExecutor

import nacl.utils
import tornado.web
from motor import MotorClient

from .handlers.auth import SignupHandler
from .handlers.testapi import TestApiHandler
from .handlers.tokens import TokenGetHandler, TokenRenewHandler

from .conf import (MONGODB_HOST, MONGODB_DBNAME,
                   APP_SECRETKEY_SIZE, WORKERS)


class Application(tornado.web.Application):

    def __init__(self):

        handlers = [
            (r'/api/signup', SignupHandler),
            (r'/api/token/get', TokenGetHandler),
            (r'/api/token/renew', TokenRenewHandler),
            (r'/api/test', TestApiHandler)
        ]

        settings = dict(
            login_url='/login',
            debug=True
        )

        super(Application, self).__init__(handlers, **settings)

        # MongoDB
        self.db = MotorClient(**MONGODB_HOST)[MONGODB_DBNAME]

        # ThreadPoolExecutor for long tasks like password hashing
        self.executor = ThreadPoolExecutor(WORKERS)

        # Secret key for HMAC
        self.hmac_key = nacl.utils.random(size=APP_SECRETKEY_SIZE)
