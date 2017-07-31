#!/usr/bin/env python
from app import db_session
# Perception
#
# Copyright (C) 2017 Avery Rozar
#
# This program is free software; you can redistribute it and/or modify it under the terms of the The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the "Software") to deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
# persons to whom the Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
# Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
# WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
# OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

from app.lib.perception_daemon import PerceptionDaemon
from time import sleep
import sys


# Local Class
# -------------------------------------------------------------------------------
class MyPerceptionDaemon(PerceptionDaemon):
    @staticmethod
    def run():
        while True:
            sleep(1)

# Main
# -------------------------------------------------------------------------------


def main():
    perceptiond = MyPerceptionDaemon('/var/run/perceptiond.pid')
    if len(sys.argv) == 2:
        if 'start' == sys.argv[1]:
            perceptiond.start()
        elif 'stop' == sys.argv[1]:
            perceptiond.stop()
        elif 'restart' == sys.argv[1]:
            perceptiond.restart()
        else:
            print("Unknown command")
            sys.exit(0)
        sys.exit(0)
    else:
        print("usage: %s start|stop|restart" % sys.argv[0])
        sys.exit(0)


if __name__ == '__main__':

    try:
        main()

    except(IOError, SystemError) as e:
        db_session.close()
        print(e)

    except KeyboardInterrupt:
        db_session.close()
        print('Crtl+C Pressed. Shutting down.')
