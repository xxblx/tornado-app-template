# -*- coding: utf-8 -*-

import tornado.httpserver
import tornado.ioloop

from webapp.app import WebApp
from webapp.conf import HOST, PORT


def main():

    http_server = tornado.httpserver.HTTPServer(WebApp())
    http_server.listen(PORT, HOST)

    tornado.ioloop.IOLoop.current().start()


if __name__ == '__main__':
    main()
