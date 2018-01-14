#!VENV/bin/python
# -*- coding: utf-8 -*-

import tornado.httpserver
import tornado.ioloop

from webapp.conf import HOST, PORT
from webapp.app import Application


def main():

    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(PORT, HOST)

    tornado.ioloop.IOLoop.current().start()


if __name__ == '__main__':
    main()
