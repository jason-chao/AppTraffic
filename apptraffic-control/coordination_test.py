import unittest
import logging
import sys
import time

import pymongo
import configparser

from coordination import * 

logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)

class TestValidator(unittest.TestCase):
    def setUp(self):
        self.validator = CoordinationValidator()
        pass

    def test_is_email(self):
        self.assertTrue(self.validator.is_valid_email("user@server.com"))
        self.assertFalse(self.validator.is_valid_email("user"))
        self.assertFalse(self.validator.is_valid_email("user@"))
        self.assertFalse(self.validator.is_valid_email("@server"))
        pass

    def test_is_valid_password(self):
        self.assertTrue(self.validator.is_valid_password("ValidPassword1234"))
        self.assertFalse(self.validator.is_valid_password(""))
        self.assertFalse(self.validator.is_valid_password("   ab   "))
        self.assertFalse(self.validator.is_valid_password("password"))
        self.assertFalse(self.validator.is_valid_password("validpassword"))
        self.assertFalse(self.validator.is_valid_password("validPassword"))
        self.assertFalse(self.validator.is_valid_password("123456789"))
        pass

    def test_is_valid_username(self):
        self.assertTrue(self.validator.is_valid_username("username"))
        self.assertFalse(self.validator.is_valid_password(""))
        self.assertFalse(self.validator.is_valid_password("  user  "))
        self.assertFalse(self.validator.is_valid_username("user"))
        self.assertFalse(self.validator.is_valid_username("12345678"))


if __name__ == '__main__':
    unittest.main()
