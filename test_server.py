import unittest
import json
import time
import requests

class TestJWKSserver(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base_url = "http://localhost:8080"
    
    def test_auth_with_valid_key(self):
        # Test authentication with a valid key
        response = requests.post(f"{self.base_url}/auth")
        self.assertEqual(response.status_code, 200)
        token = response.text
        self.assertIsNotNone(token)
    
    def test_auth_with_expired_key(self):
        # Test authentication with an expired key
        response = requests.post(f"{self.base_url}/auth?expired=True")
        self.assertEqual(response.status_code, 200)
        token = response.text
        self.assertIsNotNone(token)

    def test_jwks(self):
        # Test retrieving JWKS
        response = requests.get(f"{self.base_url}/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)
        keys = json.loads(response.text)
        self.assertIn("keys", keys)
        self.assertGreater(len(keys["keys"]), 0)

    @classmethod
    def tearDownClass(cls):
        pass


if __name__ == "__main__":
    unittest.main()