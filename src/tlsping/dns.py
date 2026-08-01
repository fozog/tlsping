from __future__ import annotations

import json
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, List, Optional

import dns.resolver

from .tls import trace


@dataclass
class RegistrarInfo:
    registrar: Optional[str] = None
    source: Optional[str] = None
    country: Optional[str] = None
    descr: Optional[str] = None
    record_maintained_by: Optional[str] = None
    source_type: Optional[str] = None


@dataclass
class NameserverInfo:
    host: str
    addresses: List[str]
    descr: Optional[str] = None
    country: Optional[str] = None
    asn: Optional[str] = None


@dataclass
class DnsReport:
    domain: str
    registrar: RegistrarInfo
    nameservers: List[NameserverInfo]
    warnings: List[str]


def _candidate_domains(hostname: str) -> List[str]:
    labels = [label for label in hostname.strip(".").split(".") if label]
    if len(labels) < 2:
        return [hostname.strip(".")]

    candidates: List[str] = []
    for i in range(len(labels) - 1):
        candidate = ".".join(labels[i:])
        if candidate not in candidates:
            candidates.append(candidate)
    return candidates


def _query_resolver(resolver: Any, domain: str, rdtype: str) -> Any:
    if hasattr(resolver, "resolve"):
        try:
            return resolver.resolve(domain, rdtype)
        except AttributeError:
            pass
    return resolver.query(domain, rdtype)


def _first_ns_domain(hostname: str) -> str:
    resolver = dns.resolver.Resolver()
    for candidate in _candidate_domains(hostname):
        try:
            answer = _query_resolver(resolver, candidate, "NS")
            if answer:
                return candidate
        except Exception:
            continue
    return hostname.strip(".")


def _answer_texts(answer: Any) -> List[str]:
    if not answer:
        return []

    values: List[str] = []
    for record in answer:
        if hasattr(record, "target") and hasattr(record.target, "to_text"):
            values.append(record.target.to_text().rstrip("."))
        elif hasattr(record, "to_text"):
            values.append(record.to_text().rstrip("."))
        elif hasattr(record, "address"):
            values.append(record.address)
        else:
            values.append(str(record).rstrip("."))
    return values


def _extract_from_raw(raw_text: str) -> RegistrarInfo:
    registrar_info = RegistrarInfo(source_type="WHOIS")

    if not raw_text:
        return registrar_info

    lines = [line.rstrip() for line in raw_text.splitlines()]
    in_registrar_block = False
    registrar_lines: List[str] = []

    for line in lines:
        stripped = line.strip()
        if not stripped:
            if in_registrar_block:
                continue
            continue

        if stripped.lower() == "registrar:":
            in_registrar_block = True
            continue

        if stripped.lower().startswith("record maintained by") or stripped.lower().startswith("record maintained by:"):
            value = stripped.split(":", 1)[1].strip() if ":" in stripped else ""
            if not registrar_info.record_maintained_by:
                registrar_info.record_maintained_by = value
            continue

        if in_registrar_block:
            if (
                stripped.lower().startswith("abuse contact")
                or stripped.lower().startswith("dnssec")
                or stripped.lower().startswith("domain nameservers")
            ):
                in_registrar_block = False
            else:
                if ":" in stripped:
                    key, value = stripped.split(":", 1)
                    normalized_key = key.strip().lower()
                    if normalized_key == "record maintained by" and not registrar_info.registrar and not registrar_lines:
                        registrar_info.registrar = value.strip()
                        continue
                    if normalized_key == "country" and not registrar_info.country:
                        registrar_info.country = value.strip()
                        break
                    if normalized_key == "record maintained by":
                        continue
                    if normalized_key in {"source"}:
                        pass
                    elif normalized_key in {"descr", "description"}:
                        if value.strip().startswith("-----BEGIN CERTIFICATE-----"):
                            continue
                        registry_descr = value.strip()
                        if registry_descr and not registrar_info.descr:
                            registrar_info.descr = registry_descr
                    else:
                        pass
                registrar_lines.append(stripped)
            continue

        if ":" not in stripped:
            continue

        key, value = stripped.split(":", 1)
        normalized_key = key.strip().lower()
        normalized_value = value.strip()

        if normalized_key == "registrar" and not registrar_info.registrar:
            registrar_info.registrar = normalized_value
        elif normalized_key == "source" and not registrar_info.source:
            registrar_info.source = normalized_value
        elif normalized_key == "country" and not registrar_info.country:
            registrar_info.country = normalized_value
        elif normalized_key in {"descr", "description"} and not getattr(registrar_info, "descr", None):
            if normalized_value.startswith("-----BEGIN CERTIFICATE-----"):
                continue
            setattr(registrar_info, "descr", normalized_value)
        elif normalized_key == "record maintained by" and not registrar_info.registrar and not registrar_lines:
            registrar_info.registrar = normalized_value

    if not registrar_info.registrar and registrar_lines:
        registrar_info.registrar = "\n".join(registrar_lines).strip()

    return registrar_info


def _to_scalar(value) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, list):
        if not value:
            return None
        return str(value[0])
    return str(value)


def _get_whois_value(whois_data: Any, attr: str) -> Any:
    if hasattr(whois_data, attr):
        return getattr(whois_data, attr)
    if isinstance(whois_data, dict):
        return whois_data.get(attr)
    return None


def _get_rdap_server(domain: str) -> Optional[str]:
    bootstrap_url = "https://data.iana.org/rdap/dns.json"
    try:
        with urllib.request.urlopen(bootstrap_url, timeout=10) as response:
            payload = response.read().decode("utf-8")
    except Exception:
        return None

    try:
        bootstrap = json.loads(payload)
    except Exception:
        return None

    labels = [label for label in domain.strip(".").split(".") if label]
    suffixes = [".".join(labels[index:]) for index in range(len(labels))]
    for suffix in suffixes:
        for service in bootstrap.get("services", []):
            if not service or len(service) < 2:
                continue
            tlds = service[0] or []
            if not isinstance(tlds, list):
                continue
            tld_values = {str(tld).lower() for tld in tlds if isinstance(tld, str)}
            if suffix.lower() in tld_values:
                urls = service[1] or []
                if isinstance(urls, list) and urls:
                    first_url = next((url for url in urls if isinstance(url, str) and url), None)
                    if first_url:
                        return first_url.rstrip("/") + "/"
    return None


def _query_rdap(domain: str) -> Optional[dict]:
    candidates = []
    server = _get_rdap_server(domain)
    if server:
        candidates.append(server.rstrip("/") + "/")
    candidates.extend(["https://rdap.org/", "https://rdap.publicinterestregistry.org/"])

    for base_url in candidates:
        endpoint_path = f"{base_url.rstrip('/')}/domain/{urllib.parse.quote(domain, safe='.') }"
        trace(f"querying RDAP: {endpoint_path}")
        try:
            with urllib.request.urlopen(endpoint_path, timeout=10) as response:
                payload = response.read().decode("utf-8")
        except Exception as exc:
            trace(f"RDAP lookup failed for {endpoint_path}: {exc}")
            continue

        try:
            parsed = json.loads(payload)
        except Exception as exc:
            trace(f"RDAP response was not valid JSON for {endpoint_path}: {exc}")
            continue

        if parsed:
            trace(f"RDAP response received for {endpoint_path}")
            return parsed
        trace(f"RDAP response empty for {endpoint_path}")

    trace("RDAP lookup produced no usable response")
    return None


def _extract_from_rdap(payload: Optional[dict]) -> RegistrarInfo:
    registrar_info = RegistrarInfo(source_type="RDAP")
    if not payload:
        return registrar_info

    entities = payload.get("entities") or []
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        if entity.get("roles") and "registrar" in [role.lower() for role in entity.get("roles", [])]:
            vcard = entity.get("vcardArray") or []
            if isinstance(vcard, list):
                for entry in vcard:
                    if not isinstance(entry, list):
                        continue
                    if not entry:
                        continue
                    if len(entry) >= 4 and isinstance(entry[0], str) and entry[0].lower() in {"fn", "org"}:
                        registrar_info.registrar = _to_scalar(entry[3])
                        break
                    if len(entry) >= 2 and isinstance(entry[1], list):
                        nested = entry[1]
                        if nested and len(nested) >= 4 and isinstance(nested[0], str) and nested[0].lower() in {"fn", "org"}:
                            registrar_info.registrar = _to_scalar(nested[3])
                            break
                    if len(entry) >= 2 and isinstance(entry[0], str) and entry[0].lower() in {"fn", "org"}:
                        registrar_info.registrar = _to_scalar(entry[1])
                        break
            break

    if not registrar_info.registrar:
        registrar_info.registrar = _to_scalar(payload.get("handle"))

    return registrar_info


def _resolve_nameservers(domain: str) -> List[NameserverInfo]:
    resolver = dns.resolver.Resolver()

    ns_hosts: List[str] = []
    try:
        trace(f"querying NS records for {domain} via resolver")
        answer = _query_resolver(resolver, domain, "NS")
        ns_hosts = _answer_texts(answer)
        trace(f"resolver returned NS results for {domain}: {ns_hosts or '<none>'}")
    except Exception as exc:
        trace(f"NS query failed for {domain}: {exc}")
        return []

    results: List[NameserverInfo] = []
    for host in sorted(set(ns_hosts)):
        addresses: List[str] = []
        try:
            trace(f"querying A records for nameserver {host}")
            a_records = _query_resolver(resolver, host, "A")
            addresses.extend(_answer_texts(a_records))
            trace(f"A record results for {host}: {addresses or '<none>'}")
        except Exception as exc:
            trace(f"A lookup failed for {host}: {exc}")
            pass

        try:
            trace(f"querying AAAA records for nameserver {host}")
            aaaa_records = _query_resolver(resolver, host, "AAAA")
            addresses.extend(_answer_texts(aaaa_records))
            trace(f"AAAA record results for {host}: {addresses or '<none>'}")
        except Exception as exc:
            trace(f"AAAA lookup failed for {host}: {exc}")
            pass

        metadata: Optional[dict] = None
        for candidate in addresses:
            trace(f"checking Cymru metadata for nameserver IP {candidate}")
            cymru_data = _collect_cymru_metadata(candidate)
            if cymru_data and (cymru_data.get("country") or cymru_data.get("asn")):
                metadata = cymru_data
                trace(
                    f"Cymru nameserver metadata found for {candidate}: "
                    f"asn={cymru_data.get('asn') or 'N/A'} country={cymru_data.get('country') or 'N/A'}"
                )
                break

            trace(f"Cymru metadata unavailable for {candidate}; trying WHOIS fallback")
            whois_data = _collect_whois_metadata(candidate)
            if whois_data:
                metadata = {"country": whois_data.get("country"), "descr": whois_data.get("descr"), "asn": None}
                trace(
                    f"WHOIS nameserver metadata found for {candidate}: "
                    f"country={metadata.get('country') or 'N/A'} descr={metadata.get('descr') or 'N/A'}"
                )
                break

        results.append(
            NameserverInfo(
                host=host,
                addresses=sorted(set(addresses)),
                descr=metadata.get("descr") if metadata else None,
                country=metadata.get("country") if metadata else None,
                asn=metadata.get("asn") if metadata else None,
            )
        )

    return results


def _query_whois(domain: str) -> Any:
    import subprocess

    trace(f"querying WHOIS for {domain}")
    completed = subprocess.run(
        ["whois", domain],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if not completed.stdout and not completed.stderr:
        raise RuntimeError("empty whois output")
    return "\n".join(part for part in [completed.stdout, completed.stderr] if part)


def _collect_cymru_metadata(ip_address: str) -> Optional[dict]:
    if not ip_address:
        return None

    query_name = ip_address
    if ":" not in ip_address:
        query_name = f"{ip_address}.origin.asn.cymru.com"
    else:
        query_name = f"{ip_address}.origin6.asn.cymru.com"

    trace(f"querying Cymru for {ip_address}")
    try:
        answers = _query_resolver(dns.resolver.Resolver(), query_name, "TXT")
    except Exception as exc:
        trace(f"Cymru lookup failed for {ip_address}: {exc}")
        return None

    for answer in answers:
        try:
            text = answer.to_text().strip().strip('"')
        except Exception:
            text = str(answer).strip().strip('"')
        if not text:
            continue
        parts = [part.strip() for part in text.split("|")]
        if len(parts) < 3:
            continue
        asn = parts[0].strip()
        country = parts[2].strip()
        if asn or country:
            return {"asn": asn, "country": country}

    return None


def _collect_whois_metadata(ip_address: str) -> Optional[dict]:
    if not ip_address:
        return None

    trace(f"querying WHOIS fallback for nameserver IP {ip_address}")
    try:
        raw_text = _query_whois(ip_address)
    except Exception as exc:
        trace(f"WHOIS fallback failed for {ip_address}: {exc}")
        return None

    if not isinstance(raw_text, str):
        raw_text = getattr(raw_text, "text", "") or ""

    parsed = _extract_from_raw(raw_text)
    result = {
        "country": parsed.country,
        "descr": parsed.descr,
    }
    if not any(result.values()):
        return None
    return result


def _collect_whois_via_library(domain: str, use_rdap: bool = True) -> Optional[RegistrarInfo]:
    if use_rdap:
        rdap_payload = _query_rdap(domain)
        rdap_info = _extract_from_rdap(rdap_payload)

        if rdap_info.registrar:
            return rdap_info

    try:
        raw_text = _query_whois(domain)
    except Exception as exc:
        trace(f"WHOIS lookup failed for {domain}: {exc}")
        return None

    if not isinstance(raw_text, str):
        raw_text = getattr(raw_text, "text", "") or ""

    parsed = _extract_from_raw(raw_text)
    if parsed.registrar or parsed.source or parsed.country or parsed.record_maintained_by:
        return parsed
    return None


def collect_dns_report(hostname: str) -> DnsReport:
    domain = _first_ns_domain(hostname)
    warnings: List[str] = []

    registrar = RegistrarInfo()
    library_whois = _collect_whois_via_library(domain)
    if library_whois:
        registrar = library_whois
    else:
        warnings.append("WHOIS lookup unavailable; registrar metadata unavailable")

    nameservers = _resolve_nameservers(domain)
    if not nameservers:
        warnings.append("authoritative nameserver lookup returned no NS records")

    return DnsReport(
        domain=domain,
        registrar=registrar,
        nameservers=nameservers,
        warnings=warnings,
    )


def display_dns_report(hostname: str, compact: bool = False) -> None:
    report = collect_dns_report(hostname)

    if compact:
        print(" [Registrar]")
        if report.registrar.registrar:
            print(f"  - name   : {report.registrar.registrar}")
        if report.registrar.record_maintained_by:
            print(f"  - record maintained by : {report.registrar.record_maintained_by}")

        print("\n [Authoritative Nameservers]")
        if report.nameservers:
            for ns in report.nameservers:
                parts = [ns.host.rstrip(".")]
                if ns.descr:
                    parts.append(f"descr: {ns.descr}")
                if ns.country:
                    parts.append(f"country: {ns.country}")
                if ns.asn:
                    parts.append(f"asn: {ns.asn}")
                print(f"  - {' | '.join(parts)}")
        else:
            print("  - N/A")
        return

    print("\n" + "=" * 60)
    print(f" DNS Summary for: {hostname}")
    print("=" * 60)
    print(f"Domain used      : {report.domain}")

    print("\n [Registrar]")
    if report.registrar.source_type:
        print(f"  - source type : {report.registrar.source_type}")
    if report.registrar.registrar:
        print(f"  - registrar   : {report.registrar.registrar}")
    if report.registrar.record_maintained_by:
        print(
            f"  - record maintained by : {report.registrar.record_maintained_by}"
        )
    if report.registrar.source:
        print(f"  - source      : {report.registrar.source}")
    if report.registrar.country:
        print(f"  - country     : {report.registrar.country}")

    print("\n [Authoritative Nameservers]")
    if report.nameservers:
        for ns in report.nameservers:
            joined_ips = ", ".join(ns.addresses) if ns.addresses else "N/A"
            descr = f" | descr: {ns.descr}" if ns.descr else ""
            country = f" | country: {ns.country}" if ns.country else ""
            asn = f" | asn: {ns.asn}" if ns.asn else ""
            print(f"  - {ns.host}: {joined_ips}{descr}{country}{asn}")
    else:
        print("  - N/A")


    if report.warnings:
        print("\n [DNS Warnings]")
        for warning in report.warnings:
            print(f"  - {warning}")

    print("=" * 60)
