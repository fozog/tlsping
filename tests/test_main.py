import unittest

from tlsping.main import build_message


class BuildMessageTests(unittest.TestCase):
    def test_build_message_contains_hello_world(self) -> None:
        message = build_message()

        self.assertIn("Hello, world!", message)
        self.assertIn("cryptography SHA-256 fingerprint:", message)
