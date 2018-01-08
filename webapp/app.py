# -*- coding: utf-8 -*-

from concurrent.futures import ThreadPoolExecutor

import nacl.utils
import tornado.web
from motor import MotorClient


class Application(tornado.web.Application):

    def __init__(self):

        handlers = [
#            (r'/', HomeHandler),
#            (r'/register', RegistrationHandler),
#            (r'/login', LoginHandler),
#            (r'/logout', LogoutHandler),
#            (r'/profile', ProfileHandler),
#            (r'/cpanel', CPanelHandler),
#            (r'/rpmbuild', RPMBuildHandler),
        ]

        settings = dict(
            login_url='/login',
            debug=True,
        )

        super(Application, self).__init__(handlers, **settings)

        # MongoDB
        self.db = MotorClient('127.0.0.1')['tornado-pynacl-tokens']

        # ThreadPoolExecutor for long tasks like password hashing
        self.executor = ThreadPoolExecutor(32)

        # Secret key for HMAC
        self.hmac_key = nacl.utils.random(size=64)
