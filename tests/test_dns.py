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

    def test_nameserver_whois_fields_are_exposed(self) -> None:
        with patch.object(dns_module.dns.resolver, "Resolver") as resolver_cls, patch.object(
            dns_module,
            "_collect_whois_via_cli",
            return_value=SimpleNamespace(descr="Netnod NDS Service", country="SE"),
        ):
            resolver_cls.return_value.resolve.side_effect = [
                [SimpleNamespace(target=SimpleNamespace(to_text=lambda: "ns1.example.com."))]
            ]
            nameservers = dns_module._resolve_nameservers("example.com")

        self.assertEqual("Netnod NDS Service", nameservers[0].descr)
        self.assertEqual("SE", nameservers[0].country)

    def test_collect_dns_report_parses_registrar_blocks_and_record_maintained_by(self) -> None:
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
                stdout="Registrar:\n   Example Registrar\n   1 Main Street\nRecord maintained by: Example Registry\nCountry: SE\n",
                stderr="",
            ),
        ), patch.object(dns_module.dns.resolver, "Resolver") as resolver_cls:
            resolver_cls.return_value.resolve.side_effect = lambda *args, **kwargs: []
            report = dns_module.collect_dns_report("example.com")

        self.assertEqual("Example Registrar\n1 Main Street", report.registrar.registrar)
        self.assertEqual("SE", report.registrar.country)

    def test_extract_from_raw_preserves_record_maintained_by(self) -> None:
        raw_text = "Registrar:\n   Example Registrar\n   1 Main Street\n\nRecord maintained by: Example Registry\nCountry: SE\n"

        parsed = dns_module._extract_from_raw(raw_text)

        self.assertEqual("Example Registrar\n1 Main Street", parsed.registrar)
        self.assertEqual("Example Registry", parsed.record_maintained_by)
        self.assertEqual("SE", parsed.country)

    def test_collect_dns_report_uses_cli_whois_fallback_for_record_maintained_by(self) -> None:
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
                stdout="Registrar:\n   Example Registrar\nRecord maintained by: Example Registry\nCountry: SE\n",
                stderr="",
            ),
        ), patch.object(dns_module.dns.resolver, "Resolver") as resolver_cls:
            resolver_cls.return_value.resolve.side_effect = lambda *args, **kwargs: []
            report = dns_module.collect_dns_report("example.com")

        self.assertEqual("Example Registry", report.registrar.record_maintained_by)

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

    def test_resolve_nameservers_uses_ip_whois_metadata(self) -> None:
        class FakeResolver:
            def __init__(self) -> None:
                self.calls = []

            def resolve(self, domain: str, rdtype: str):
                if domain == "example.com" and rdtype == "NS":
                    return [SimpleNamespace(target=SimpleNamespace(to_text=lambda: "ns1.example.com."))]
                if domain == "ns1.example.com" and rdtype == "A":
                    return [SimpleNamespace(address="192.0.2.1")]
                if domain == "ns1.example.com" and rdtype == "AAAA":
                    return []
                raise AssertionError(f"unexpected lookup: {domain} {rdtype}")

            def query(self, domain: str, rdtype: str):
                raise AssertionError(f"query should not be used: {domain} {rdtype}")

        fake_resolver = FakeResolver()

        def fake_collect_whois(target: str):
            if target == "192.0.2.1":
                return SimpleNamespace(descr="Netnod NDS Service", country="SE", registrar=None, source=None)
            return None

        with patch.object(dns_module.dns.resolver, "Resolver", return_value=fake_resolver), patch.object(
            dns_module,
            "_collect_whois_via_cli",
            side_effect=fake_collect_whois,
        ):
            nameservers = dns_module._resolve_nameservers("example.com")

        self.assertEqual(1, len(nameservers))
        self.assertEqual("Netnod NDS Service", nameservers[0].descr)
        self.assertEqual("SE", nameservers[0].country)
