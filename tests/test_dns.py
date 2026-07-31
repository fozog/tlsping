import builtins
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tlsping import dns as dns_module


class DnsCompatibilityTests(unittest.TestCase):
    def test_resolve_nameservers_falls_back_to_query(self) -> None:
        class FakeResolver:
            def __init__(self) -> None:
                self.calls = []

            def resolve(self, domain: str, rdtype: str):
                raise AttributeError("resolve")

            def query(self, domain: str, rdtype: str):
                self.calls.append((domain, rdtype))
                return [SimpleNamespace(target=SimpleNamespace(to_text=lambda: "ns1.example.com."))]

        fake_resolver = FakeResolver()

        with patch.object(dns_module.dns.resolver, "Resolver", return_value=fake_resolver):
            nameservers = dns_module._resolve_nameservers("example.com")

        self.assertEqual(["ns1.example.com"], [ns.host for ns in nameservers])
        self.assertIn(("example.com", "NS"), fake_resolver.calls)

    def test_collect_dns_report_uses_cli_whois_fallback(self) -> None:
        original_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "whois":
                raise ImportError("python-whois unavailable")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=fake_import), patch.object(
            dns_module.subprocess,
            "run",
            return_value=SimpleNamespace(
                returncode=0,
                stdout="Registrar: Example Registrar\nCountry: SE\n",
                stderr="",
            ),
        ), patch.object(dns_module.dns.resolver, "Resolver") as resolver_cls:
            resolver_cls.return_value.resolve.side_effect = lambda *args, **kwargs: []
            report = dns_module.collect_dns_report("example.com")

        self.assertEqual("Example Registrar", report.registrar.registrar)
        self.assertEqual("SE", report.registrar.country)
        self.assertTrue(all("WHOIS" not in warning for warning in report.warnings))
