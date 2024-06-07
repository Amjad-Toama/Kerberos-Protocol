import unittest
from unittest.mock import mock_open, patch
from Crypto.Random import get_random_bytes

from fileValidity import *
from validators import *


class TestValidators(unittest.TestCase):
    def test_is_valid_ipv4(self):
        self.assertTrue(is_valid_ipv4("192.168.1.1"))
        self.assertTrue(is_valid_ipv4("255.255.255.255"))
        self.assertFalse(is_valid_ipv4("256.256.256.256"))
        self.assertFalse(is_valid_ipv4("192.168.1"))
        self.assertFalse(is_valid_ipv4("192.168.1.1.1"))
        self.assertFalse(is_valid_ipv4("192.168.1.256"))

    def test_is_valid_port(self):
        self.assertTrue(is_valid_port("65535"))
        self.assertTrue(is_valid_port("80"))
        self.assertFalse(is_valid_port(80))
        self.assertFalse(is_valid_port(65536))
        self.assertFalse(is_valid_port(-1))
        self.assertFalse(is_valid_port(3.14))
        self.assertFalse(is_valid_port(None))

    def test_is_valid_endpoint(self):
        self.assertTrue(is_valid_endpoint("192.168.1.1:80"))            # valid endpoint
        self.assertTrue(is_valid_endpoint("255.255.255.255:65535"))     # valid endpoint
        self.assertFalse(is_valid_endpoint("255.255.255.255:-1"))       # valid ip, invalid port
        self.assertFalse(is_valid_endpoint("256.256.256.256:8080"))     # invalid ip, valid port
        self.assertFalse(is_valid_endpoint("192.168.1.256:65536"))      # invalid ip, invalid port

    def test_is_valid_password_length(self):
        self.assertTrue(is_valid_password("short"))
        self.assertTrue(is_valid_password("a" * 254))  # 254 characters, should be valid
        self.assertTrue(is_valid_password("a" * 255))  # 255 characters, should be valid
        self.assertFalse(is_valid_password("a" * 256))  # 256 characters, should be invalid
        self.assertFalse(is_valid_password(12345))  # Non-string input should return False
        self.assertFalse(is_valid_password(None))  # Non-string input should return False

    def test_is_valid_username(self):
        self.assertTrue(is_valid_name("Alice"))
        self.assertTrue(is_valid_name("Bob"))
        self.assertTrue(is_valid_name("Alice123"))  # Contains numbers
        self.assertTrue(is_valid_name("Alice!"))  # Contains special character
        self.assertFalse(is_valid_name(""))  # Empty string, should be invalid
        self.assertTrue(is_valid_name("A" * 255))  # 255 characters, should be valid
        self.assertFalse(is_valid_name("A" * 256))  # 256 characters, should be invalid
        self.assertFalse(is_valid_name(12345))  # Non-string input should return False
        self.assertFalse(is_valid_name(None))  # Non-string input should return False

    def test_is_valid_uuid(self):
        self.assertTrue(is_valid_uuid("dd5c8bb5c9567df45f044fd7674f660e"))  # 16 bytes, should be valid
        self.assertFalse(is_valid_uuid("14b5e250b36f8ffa065ccc3c7ade7b6dcd"))  # should be invalid
        # self.assertFalse(is_valid_uuid("dd5c8bb5c9567df45f044fd7"))  # 17 bytes, should be invalid
        # self.assertFalse(is_valid_uuid(b"1234567890123456"))  # not str, should be invalid
        # self.assertFalse(is_valid_uuid(1234567890123456))  # not str, should be invalid
        # self.assertFalse(is_valid_uuid(None))  # None, should be invalid

    def test_is_valid_datetime(self):
        self.assertTrue(is_valid_datetime("2024-06-07 01:19:03.248528"))  # Valid datetime
        self.assertFalse(is_valid_datetime("2024-06-07 01:19:03"))  # Missing microseconds
        self.assertFalse(is_valid_datetime("2024-06-07"))  # Missing time
        self.assertFalse(is_valid_datetime("01:19:03.248528"))  # Missing date
        self.assertFalse(is_valid_datetime("2024/06/07 01:19:03.248528"))  # Wrong date separator
        self.assertFalse(is_valid_datetime("2024-06-07 25:19:03.248528"))  # Invalid hour
        self.assertFalse(is_valid_datetime("invalid string"))  # Completely invalid format
        self.assertFalse(is_valid_datetime(None))  # None, should be invalid

    def test_valid_key(self):
        key = get_random_bytes(32)
        encoded_key = base64.b64encode(key).decode('utf-8')
        self.assertTrue(is_valid_64base_symmetric_key(encoded_key))

    def test_invalid_base64_key(self):
        invalid_key = "invalid_base64_key"
        self.assertFalse(is_valid_64base_symmetric_key(invalid_key))

    def test_short_key(self):
        key = get_random_bytes(16)
        encoded_key = base64.b64encode(key).decode('utf-8')
        self.assertFalse(is_valid_64base_symmetric_key(encoded_key))

    def test_long_key(self):
        key = get_random_bytes(64)
        encoded_key = base64.b64encode(key).decode('utf-8')
        self.assertFalse(is_valid_64base_symmetric_key(encoded_key))

    def test_empty_string(self):
        self.assertFalse(is_valid_64base_symmetric_key(""))

    def test_non_string_input(self):
        self.assertFalse(is_valid_64base_symmetric_key(None))
        self.assertFalse(is_valid_64base_symmetric_key(12345))
        self.assertFalse(is_valid_64base_symmetric_key([]))
        self.assertFalse(is_valid_64base_symmetric_key({}))


class TestIsValidFileToOpen(unittest.TestCase):
    @patch("builtins.open", new_callable=mock_open)
    def test_file_exists_and_accessible(self, mock_open):
        # Mocking the open function to simulate a file that can be opened successfully
        mock_open.return_value.__enter__.return_value = None
        self.assertTrue(is_valid_file_to_open("existing_file.txt", "r"))

    @patch("builtins.open", side_effect=FileNotFoundError)
    def test_file_not_found(self, mock_open):
        # Mocking the open function to simulate a FileNotFoundError
        self.assertFalse(is_valid_file_to_open("non_existent_file.txt", "r"))

    @patch("builtins.open", side_effect=PermissionError)
    def test_permission_denied(self, mock_open):
        # Mocking the open function to simulate a PermissionError
        self.assertFalse(is_valid_file_to_open("no_permission_file.txt", "r"))

    @patch("builtins.open", side_effect=Exception("Some error"))
    def test_general_exception(self, mock_open):
        # Mocking the open function to simulate a general exception
        self.assertFalse(is_valid_file_to_open("error_file.txt", "r"))

    def test_none_file_type(self):
        self.assertFalse(is_valid_file_to_open("abc", "r"))


class TestIsValidPortFile(unittest.TestCase):
    @patch("builtins.open", new_callable=mock_open, read_data="8080\n")
    def test_valid_port_file1(self, mock_open):
        self.assertTrue(is_valid_port_file("valid_port_file.info"))

    @patch("builtins.open", new_callable=mock_open, read_data="8080")
    def test_valid_port_file2(self, mock_open):
        self.assertTrue(is_valid_port_file("valid_port_file.info"))

    @patch("builtins.open", new_callable=mock_open, read_data="8080")
    def test_invalid_port_file1(self, mock_open):
        self.assertFalse(is_valid_port_file("valid_port_file.text"))

    @patch("builtins.open", new_callable=mock_open, read_data="8080 not_a_valid_port\n")
    def test_invalid_port_file2(self, mock_open):
        self.assertFalse(is_valid_port_file("invalid_port_file.info"))

    @patch("builtins.open", new_callable=mock_open, read_data="8080 \nnot_a_valid_port")
    def test_invalid_port_file3(self, mock_open):
        self.assertFalse(is_valid_port_file("invalid_port_file.info"))

    @patch("builtins.open", new_callable=mock_open, read_data="not_a_valid_port\n")
    def test_invalid_port_file4(self, mock_open):
        self.assertFalse(is_valid_port_file("invalid_port_file.info"))

    @patch("builtins.open", side_effect=FileNotFoundError)
    def test_missing_file(self, mock_open):
        self.assertFalse(is_valid_port_file("non_existent_file.info"))


class TestIsValidSrvFile(unittest.TestCase):
    @patch("builtins.open", new_callable=mock_open, read_data="127.0.0.1:5555\n127.0.0.1:9999\n")
    def test_valid_srv_file(self, mock_open):
        self.assertTrue(is_valid_srv_file("valid_srv_file.info"))

    @patch("builtins.open", new_callable=mock_open, read_data="127.0.0.1:5555\n127.0.0.1:9999\n")
    def test_invalid_srv_file1(self, mock_open):
        self.assertFalse(is_valid_srv_file("valid_srv_file.txt"))

    @patch("builtins.open", new_callable=mock_open, read_data="127.0.0.1:5555\n127.0.0.1:9999\n")
    def test_invalid_srv_file2(self, mock_open):
        self.assertFalse(is_valid_srv_file("valid_srv_file.text"))

    @patch("builtins.open", new_callable=mock_open, read_data="127.0.0.1:5555\ninvalid file\n")
    def test_invalid_srv_file3(self, mock_open):
        self.assertFalse(is_valid_srv_file("valid_srv_file.info"))

    @patch("builtins.open", new_callable=mock_open, read_data="invalid123\n127.0.0.1:9999\n")
    def test_invalid_srv_file4(self, mock_open):
        self.assertFalse(is_valid_srv_file("valid_srv_file.info"))

    @patch("builtins.open", side_effect=FileNotFoundError)
    def test_invalid_srv_file5(self, mock_open):
        self.assertFalse(is_valid_srv_file("valid_srv_file.info"))


class TestIsValidMsgFile(unittest.TestCase):
    # valid file
    @patch("builtins.open", new_callable=mock_open, read_data="127.0.0.1:9999\nPrinter 20\n"
                                                              "64f3f63985f04beb81a0e43321880182\n"
                                                              "k5XY8Iu9LhItYLga7k9pcYrd76UQhqY4WTVjDGv2DMg=\n")
    def test_valid_msg_file1(self, mock_open):
        self.assertTrue(is_valid_msg_file("valid_srv_file.info"))

    @patch("builtins.open", new_callable=mock_open, read_data="127.0.0.1:9999\nPrinter 20\n"
                                                              "64f3f63985f04beb81a0e43321880182\n"
                                                              "k5XY8Iu9LhItYLga7k9pcYrd76UQhqY4WTVjDGv2DMg=\n")
    def test_valid_msg_file2(self, mock_open):
        self.assertFalse(is_valid_msg_file("valid_srv_file.txt"))

    # invalid amount of lines
    @patch("builtins.open", new_callable=mock_open, read_data="127.0.0.1:9999\nPrinter 20\n"
                                                              "64f3f63985f04beb81a0e43321880182\n"
                                                              "k5XY8Iu9LhItYLga7k9pcYrd76UQhqY4WTVjDGv2DMg=\n"
                                                              "invalid file")
    def test_invalid_msg_file(self, mock_open):
        self.assertFalse(is_valid_msg_file("invalid_srv_file.info"))

    # invalid ip address
    @patch("builtins.open", new_callable=mock_open, read_data="256.0.0.1:9999\nPrinter 20\n"
                                                              "64f3f63985f04beb81a0e43321880182\n"
                                                              "k5XY8Iu9LhItYLga7k9pcYrd76UQhqY4WTVjDGv2DMg=\n")
    def test_invalid_msg_file1(self, mock_open):
        self.assertFalse(is_valid_msg_file("invalid_srv_file.info"))

    # invalid port
    @patch("builtins.open", new_callable=mock_open, read_data="256.0.0.1:99999\nPrinter 20\n"
                                                              "64f3f63985f04beb81a0e43321880182\n"
                                                              "k5XY8Iu9LhItYLga7k9pcYrd76UQhqY4WTVjDGv2DMg=\n")
    def test_invalid_msg_file2(self, mock_open):
        self.assertFalse(is_valid_msg_file("invalid_srv_file.info"))

    # invalid name
    @patch("builtins.open", new_callable=mock_open, read_data=f"256.0.0.1:8080\n{256 * 'a'}\n"
                                                              "64f3f63985f04beb81a0e43321880182\n"
                                                              "k5XY8Iu9LhItYLga7k9pcYrd76UQhqY4WTVjDGv2DMg=\n")
    def test_invalid_msg_file3(self, mock_open):
        self.assertFalse(is_valid_msg_file("invalid_srv_file.info"))

    # line content
    @patch("builtins.open", new_callable=mock_open, read_data="256.0.0.1:8080 abcd\nPrinter 20\n"
                                                              "64f3f63985f04beb81a0e43321880182\n"
                                                              "k5XY8Iu9LhItYLga7k9pcYrd76UQhqY4WTVjDGv2DMg=\n")
    def test_invalid_msg_file4(self, mock_open):
        self.assertFalse(is_valid_msg_file("invalid_srv_file.info"))

    # line content
    @patch("builtins.open", new_callable=mock_open, read_data="256.0.0.1:8080\nPrinter 20\n"
                                                              "64f3f63985f04beb81a0e43321880182\n"
                                                              "k5XY8Iu9LhItYLga7k9pcYrd76UQhqY4WTVjDGv2DMg= abcd\n")
    def test_invalid_msg_file5(self, mock_open):
        self.assertFalse(is_valid_msg_file("invalid_srv_file.info"))


class TestIsValidMeInfo(unittest.TestCase):
    # valid file
    @patch("builtins.open", new_callable=mock_open, read_data="pikachu electric\n"
                                                              "46c67bcd7400777b1016ebe70d7b7b5e")
    def test_valid_me_file(self, mock_open):
        self.assertTrue(is_valid_me_info("valid_me_file.info"))

    # valid file
    @patch("builtins.open", new_callable=mock_open, read_data="pikachu electric\n"
                                                              "619c47487e27b811a0bfaf3e91806d5d\n")
    def test_invalid_me_file1(self, mock_open):
        self.assertTrue(is_valid_me_info("valid_me_file.info"))

    @patch("builtins.open", new_callable=mock_open, read_data="pikachu electric\n"
                                                              "619c47487e27b811a0bfaf3e91806d5d\n")
    def test_invalid_me_file2(self, mock_open):
        self.assertFalse(is_valid_me_info("valid_me_file.txt"))

    # line amount invalid
    @patch("builtins.open", new_callable=mock_open, read_data="pikachu electric\n"
                                                              "619c47487e27b811a0bfaf3e91806d5d\n"
                                                              "invalid file :(")
    def test_invalid_me_file3(self, mock_open):
        self.assertFalse(is_valid_me_info("invalid_me_file.info"))

    # invalid line token amount
    @patch("builtins.open", new_callable=mock_open, read_data="pikachu electric\n"
                                                              "619c47487e27b811a0bfaf3e91806d5d :(\n")
    def test_invalid_me_file4(self, mock_open):
        self.assertFalse(is_valid_me_info("invalid_me_file.info"))


if __name__ == '__main__':
    unittest.main()
