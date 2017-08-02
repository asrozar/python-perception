#!/usr/bin/env python
from perception import db_session
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
from perception import __version__
from perception.lib.cli import cli_loop
from socket import gethostname

g = {}

# Main
# -------------------------------------------------------------------------------


def main():
    hostname = gethostname()
    g['prefix'] = '%s' % hostname
    g['mode'] = '>'

    # begin th cli loop
    cli_loop(g['prefix'], g['mode'], __version__)

if __name__ == '__main__':

    try:
        main()

    except(IOError, SystemError) as e:
        db_session.close()
        print(e)

    except KeyboardInterrupt:
        db_session.close()
        print('Crtl+C Pressed. Shutting down.')

    except Exception as main_e:
        db_session.close()
        print(str(main_e))
