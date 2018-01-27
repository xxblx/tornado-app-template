# -*- coding: utf-8 -*-

import tornado.web
import tornado.gen

from .base import BaseHandler


class WebAuthHandler(BaseHandler):
    def get_current_user(self):
        return self.get_secure_cookie('username')


class LoginHandler(WebAuthHandler):
    def get(self):
        if self.get_current_user():
            self.redirect('/')
        else:
            self.render('login.html')

    @tornado.gen.coroutine
    def post(self):
        username = self.get_argument('username')
        password = self.get_argument('password')

        user_dct = yield self.db.users.find_one({'username': username})
        if user_dct is None:
            raise tornado.web.HTTPError(403, 'invalid username')

        # Password verify
        passwd_check = yield self.verify_password(
            user_dct['password_hash'],
            tornado.escape.utf8(password)
        )
        if not passwd_check:
            raise tornado.web.HTTPError(403, 'invalid password')

        self.set_secure_cookie('username', username)
        self.redirect(self.get_argument('next', '/'))


class LogoutHandler(WebAuthHandler):
    def get(self):
        if self.get_current_user():
            self.clear_cookie('username')
        self.redirect(self.get_argument('next', '/'))
