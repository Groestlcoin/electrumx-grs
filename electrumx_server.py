#!/usr/bin/env python3
#
# Copyright (c) 2016, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Script to kick off the server.'''

import logging
import traceback

from server.env import Env
from server.controller import Controller


def main():
    '''Set up logging and run the server.'''
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(levelname)-7s %(message)-100s '
                               '[%(filename)s:%(lineno)d]')
    logging.info('ElectrumX-GRS server starting')
    try:
        controller = Controller(Env())
        controller.run()
    except Exception:
        traceback.print_exc()
        logging.critical('ElectrumX-GRS server terminated abnormally')
    else:
        logging.info('ElectrumX-GRS server terminated normally')


if __name__ == '__main__':
    main()
