#!/usr/bin/env python3
"""
    Helper class to print content to std
"""

class PrintHelper(object):
    def __init__(self):
        self.logger = None # TODO Incase we can't to add a logger

    def received(self, msg):
        """
        Function used to print received information
        """
        print("\033[0;33m{0}\n\033[0m".format(msg));

    def sent(self, msg):
        """
        Function used to print sent information
        """
        print("\033[0;32m{0}\n\033[0m".format(msg));
