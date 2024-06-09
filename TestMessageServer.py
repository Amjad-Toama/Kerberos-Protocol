import unittest
from MessageServer import *
from Constants import VERSION


class TestMessageServer(unittest.TestCase):

    def setUp(self):
        self.authenticator_base = {
            'version': VERSION,
            'client_uuid': bytes.fromhex('ebaf87c398f52cdaf16a6f623cffa26c'),
            'server_uuid': bytes.fromhex('312a9449d65ddddccadc8226f64e4db4'),
            'creation_time': datetime.now()
        }
        self.ticket_base = {
            'version': VERSION,
            'client_uuid': bytes.fromhex('ebaf87c398f52cdaf16a6f623cffa26c'),
            'server_uuid': bytes.fromhex('312a9449d65ddddccadc8226f64e4db4'),
        }

    def test_is_valid_authenticator(self):
        authenticator = self.authenticator_base.copy()
        ticket = self.ticket_base.copy()

        # Valid authenticator
        self.assertTrue(MessageServer.is_valid_authenticator(authenticator, ticket))

        # Invalid - Version incompatible
        authenticator['version'] = 1
        self.assertFalse(MessageServer.is_valid_authenticator(authenticator, ticket))

        # Invalid - clients UUID incompatible
        authenticator = self.authenticator_base.copy()
        authenticator['client_uuid'] = bytes.fromhex('dc31ebbad5b94fbd1fd0db7f81cb4b1d')
        self.assertFalse(MessageServer.is_valid_authenticator(authenticator, ticket))

        # Invalid - server UUID incompatible
        authenticator = self.authenticator_base.copy()
        authenticator['server_uuid'] = bytes.fromhex('6a93c0ff2138f38b63b04c7abdf8b53c')
        self.assertFalse(MessageServer.is_valid_authenticator(authenticator, ticket))

        # Invalid - expired timestamp
        authenticator = self.authenticator_base.copy()
        authenticator['creation_time'] = authenticator['creation_time'] + timedelta(hours=AUTHENTICATOR_LIFETIME + 10)
        self.assertFalse(MessageServer.is_valid_authenticator(authenticator, ticket))