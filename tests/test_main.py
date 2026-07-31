import io
import unittest
from contextlib import redirect_stderr

import tlsping.main as main
from tlsping.main import resolve_port_spec


class TraceBehaviorTests(unittest.TestCase):
    def tearDown(self) -> None:
        main.set_trace_enabled(False)

    def test_trace_is_silent_by_default(self) -> None:
        buffer = io.StringIO()

        with redirect_stderr(buffer):
            main.trace("hidden")

        self.assertEqual("", buffer.getvalue())

    def test_trace_prints_when_enabled(self) -> None:
        buffer = io.StringIO()

        main.set_trace_enabled(True)
        with redirect_stderr(buffer):
            main.trace("visible")

        self.assertEqual("[TRACE] visible\n", buffer.getvalue())


class PortResolutionTests(unittest.TestCase):
    def test_resolve_port_spec_defaults_to_https(self) -> None:
        port, starttls = resolve_port_spec(None)

        self.assertEqual(443, port)
        self.assertIsNone(starttls)
