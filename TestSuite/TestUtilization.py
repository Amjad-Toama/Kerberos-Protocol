import unittest
from Utilization import *


class TestNonceMethods(unittest.TestCase):
    def test_nonce_update(self):
        # Test case 1: Nonce value is 10
        nonce = (10).to_bytes(8, byteorder='big')
        expected_result = (9).to_bytes(8, byteorder='big')
        self.assertEqual(nonce_update(nonce), expected_result)

        # Test case 2: Nonce value is 0
        nonce = (0).to_bytes(8, byteorder='big')
        expected_result = ().to_bytes(8, byteorder='big')
        self.assertEqual(nonce_update(nonce), expected_result)

    def test_get_value(self):
        # Test case 1: Nonce value is 5
        nonce = (5).to_bytes(8, byteorder='big')
        expected_result = 5
        self.assertEqual(get_value(nonce), expected_result)

        # Test case 2: Nonce value is 255
        nonce = (255).to_bytes(8, byteorder='big')
        expected_result = 255
        self.assertEqual(get_value(nonce), expected_result)


if __name__ == '__main__':
    unittest.main()
