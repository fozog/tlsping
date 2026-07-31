import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import tlsping.tls as tls
import tlsping.main as main_module
from tlsping.main import resolve_port_spec


class TraceBehaviorTests(unittest.TestCase):
    def tearDown(self) -> None:
        tls.set_trace_enabled(False)

    def test_trace_is_silent_by_default(self) -> None:
        buffer = io.StringIO()

        with redirect_stderr(buffer):
            tls.trace("hidden")

        self.assertEqual("", buffer.getvalue())

    def test_trace_prints_when_enabled(self) -> None:
        buffer = io.StringIO()

        tls.set_trace_enabled(True)
        with redirect_stderr(buffer):
            tls.trace("visible")

        self.assertEqual("[TRACE] visible\n", buffer.getvalue())


class PortResolutionTests(unittest.TestCase):
    def test_resolve_port_spec_defaults_to_https(self) -> None:
        port, starttls = resolve_port_spec(None)

        self.assertEqual(443, port)
        self.assertIsNone(starttls)

    def test_compact_output_includes_subject_and_issuer_fields(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024, backend=default_backend())
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Jose"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Cisco Systems Inc."),
            x509.NameAttribute(NameOID.COMMON_NAME, "www.cisco.com"),
        ])
        issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IdenTrust"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "HydrantID Trusted Certificate Service"),
            x509.NameAttribute(NameOID.COMMON_NAME, "HydrantID Server CA O1"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(datetime.utcnow() - timedelta(days=1))
            .not_valid_after(datetime.utcnow() + timedelta(days=1))
            .sign(key, hashes.SHA256(), backend=default_backend())
        )
        der = cert.public_bytes(serialization.Encoding.DER)

        buffer = io.StringIO()
        with patch.object(main_module, "assess_os_trust", return_value=(True, None)):
            with redirect_stdout(buffer):
                main_module._display_compact_tls_summary(
                    "www.example.com",
                    443,
                    der,
                    {},
                    "TLSv1.3",
                    ("TLS_AES_256_GCM_SHA384", "256", 1),
                )

        output = buffer.getvalue()
        self.assertIn("countryName: US", output)
        self.assertIn("stateOrProvinceName: California", output)
        self.assertIn("organizationName: Cisco Systems Inc.", output)
        self.assertIn("commonName: www.cisco.com", output)
        self.assertIn("organizationalUnitName: HydrantID Trusted Certificate Service", output)
        self.assertIn("commonName: HydrantID Server CA O1", output)
