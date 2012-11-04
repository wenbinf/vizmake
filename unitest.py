#!/usr/bin/env python

import logging
import sys
import unittest
import vizmake

class TestVizMake(unittest.TestCase):
    def setUp(self):
        try:
            self._viz = vizmake.VizMake()
        except:
            logging.error('Failed to create VizMake object')
            sys.exit(0)

    def test_get_makedb(self):
        pass

if __name__ == '__main__':
    logging.basicConfig(level=logging.ERROR,
                        format='%(asctime)s - %(levelname)-8s %(message)s')
    unittest.main()
