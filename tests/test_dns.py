import unittest
from io import BytesIO
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

    def test_nameserver_cymru_fields_are_exposed(self) -> None:
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

        with patch.object(dns_module.dns.resolver, "Resolver", return_value=fake_resolver), patch.object(
            dns_module,
            "_collect_cymru_metadata",
            return_value={"asn": "AS12345", "country": "SE"},
        ):
            nameservers = dns_module._resolve_nameservers("example.com")

        self.assertEqual("AS12345", nameservers[0].asn)
        self.assertEqual("SE", nameservers[0].country)

    def test_collect_dns_report_parses_registrar_blocks_and_record_maintained_by(self) -> None:
        fake_whois_data = SimpleNamespace(
            registrar=None,
            country=None,
            source=None,
            text="Registrar:\n   Example Registrar\n   1 Main Street\n\nRecord maintained by: Example Registry\nCountry: SE\n",
        )

        with patch.object(dns_module, "_query_rdap", return_value=None), patch.object(
            dns_module,
            "_query_whois",
            return_value=fake_whois_data,
        ), patch.object(dns_module.dns.resolver, "Resolver") as resolver_cls:
            resolver_cls.return_value.resolve.side_effect = lambda *args, **kwargs: []
            report = dns_module.collect_dns_report("example.com")

        self.assertEqual("Example Registrar\n1 Main Street", report.registrar.registrar)
        self.assertEqual("Example Registry", report.registrar.record_maintained_by)
        self.assertEqual("SE", report.registrar.country)

    def test_extract_from_raw_preserves_record_maintained_by(self) -> None:
        raw_text = "Registrar:\n   Example Registrar\n   1 Main Street\n\nRecord maintained by: Example Registry\nCountry: SE\n"

        parsed = dns_module._extract_from_raw(raw_text)

        self.assertEqual("Example Registrar\n1 Main Street", parsed.registrar)
        self.assertEqual("Example Registry", parsed.record_maintained_by)
        self.assertEqual("SE", parsed.country)

    def test_extract_from_raw_sets_source_type(self) -> None:
        parsed = dns_module._extract_from_raw("Registrar:\nExample Registrar\n")

        self.assertEqual("WHOIS", parsed.source_type)
        self.assertEqual("Example Registrar", parsed.registrar)

    def test_extract_from_rdap_sets_source_type(self) -> None:
        payload = {
            "entities": [
                {
                    "roles": ["registrar"],
                    "vcardArray": [[], ["fn", "Example Registrar"]],
                }
            ]
        }

        parsed = dns_module._extract_from_rdap(payload)

        self.assertEqual("RDAP", parsed.source_type)
        self.assertEqual("Example Registrar", parsed.registrar)

    def test_get_rdap_server_uses_iana_bootstrap(self) -> None:
        class FakeResponse:
            def __init__(self, payload: str) -> None:
                self._payload = payload.encode("utf-8")

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return self._payload

        bootstrap_payload = '{"services": [[ ["org"], ["https://rdap.publicinterestregistry.org/"] ]]}'

        with patch.object(dns_module.urllib.request, "urlopen", return_value=FakeResponse(bootstrap_payload)):
            server = dns_module._get_rdap_server("ietf.org")

        self.assertEqual("https://rdap.publicinterestregistry.org/", server)

    def test_get_rdap_server_matches_parent_domain_suffixes(self) -> None:
        class FakeResponse:
            def __init__(self, payload: str) -> None:
                self._payload = payload.encode("utf-8")

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return self._payload

        bootstrap_payload = '{"services": [[ ["com"], ["https://rdap.verisign.com/"] ]]}'

        with patch.object(dns_module.urllib.request, "urlopen", return_value=FakeResponse(bootstrap_payload)):
            server = dns_module._get_rdap_server("www.cisco.com")

        self.assertEqual("https://rdap.verisign.com/", server)

    def test_collect_dns_report_uses_library_whois_data(self) -> None:
        fake_whois_data = SimpleNamespace(
            registrar="Example Registrar",
            country="SE",
            source=None,
            text="Registrar:\n   Example Registrar\n\nRecord maintained by: Example Registry\nCountry: SE\n",
        )

        with patch.object(dns_module, "_query_rdap", return_value=None), patch.object(
            dns_module,
            "_query_whois",
            return_value=fake_whois_data,
        ), patch.object(dns_module.dns.resolver, "Resolver") as resolver_cls:
            resolver_cls.return_value.resolve.side_effect = lambda *args, **kwargs: []
            report = dns_module.collect_dns_report("example.com")

        self.assertEqual("Example Registrar", report.registrar.registrar)
        self.assertEqual("Example Registry", report.registrar.record_maintained_by)
        self.assertEqual("SE", report.registrar.country)
        self.assertTrue(all("WHOIS" not in warning for warning in report.warnings))

    def test_resolve_nameservers_uses_cymru_metadata(self) -> None:
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

        def fake_collect_cymru(target: str):
            if target == "192.0.2.1":
                return {"asn": "AS12345", "country": "SE"}
            return None

        with patch.object(dns_module.dns.resolver, "Resolver", return_value=fake_resolver), patch.object(
            dns_module,
            "_collect_cymru_metadata",
            side_effect=fake_collect_cymru,
        ):
            nameservers = dns_module._resolve_nameservers("example.com")

        self.assertEqual(1, len(nameservers))
        self.assertEqual("AS12345", nameservers[0].asn)
        self.assertEqual("SE", nameservers[0].country)

    def test_resolve_nameservers_does_not_query_rdap_for_metadata(self) -> None:
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

        with patch.object(dns_module.dns.resolver, "Resolver", return_value=fake_resolver), patch.object(
            dns_module,
            "_query_rdap",
            side_effect=AssertionError("RDAP should not be used for nameserver metadata"),
        ), patch.object(
            dns_module,
            "_collect_cymru_metadata",
            return_value={"asn": "AS12345", "country": "SE"},
        ):
            nameservers = dns_module._resolve_nameservers("example.com")

        self.assertEqual(1, len(nameservers))
        self.assertEqual("AS12345", nameservers[0].asn)
        self.assertEqual("SE", nameservers[0].country)

    def test_resolve_nameservers_falls_back_to_whois_when_cymru_fails(self) -> None:
        class FakeResolver:
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

        with patch.object(dns_module.dns.resolver, "Resolver", return_value=fake_resolver), patch.object(
            dns_module,
            "_collect_cymru_metadata",
            return_value=None,
        ), patch.object(
            dns_module,
            "_collect_whois_metadata",
            return_value={"country": "SE", "descr": "Netnod"},
        ):
            nameservers = dns_module._resolve_nameservers("example.com")

        self.assertEqual(1, len(nameservers))
        self.assertEqual("SE", nameservers[0].country)
        self.assertEqual("Netnod", nameservers[0].descr)
        self.assertIsNone(nameservers[0].asn)

    def test_resolve_nameservers_uses_only_ns_host_and_ips_for_whois_metadata(self) -> None:
        class FakeResolver:
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
        seen_targets = []

        def fake_collect_cymru(target: str):
            seen_targets.append(target)
            return None

        with patch.object(dns_module.dns.resolver, "Resolver", return_value=fake_resolver), patch.object(
            dns_module,
            "_collect_cymru_metadata",
            side_effect=fake_collect_cymru,
        ):
            dns_module._resolve_nameservers("example.com")

        self.assertEqual(["192.0.2.1"], seen_targets)

