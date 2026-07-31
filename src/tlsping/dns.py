from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import dns.resolver


@dataclass
class RegistrarInfo:
    registrar: Optional[str] = None
    source: Optional[str] = None
    country: Optional[str] = None
    descr: Optional[str] = None
    record_maintained_by: Optional[str] = None


@dataclass
class NameserverInfo:
    host: str
    addresses: List[str]
    descr: Optional[str] = None
    country: Optional[str] = None


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


def _extract_from_raw(raw_text: str) -> RegistrarInfo:
    registrar_info = RegistrarInfo()

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


def _resolve_nameservers(domain: str) -> List[NameserverInfo]:
    resolver = dns.resolver.Resolver()

    ns_hosts: List[str] = []
    try:
        answer = _query_resolver(resolver, domain, "NS")
        ns_hosts = [
            record.target.to_text().rstrip(".") if hasattr(record.target, "to_text") else str(record.target).rstrip(".")
            for record in answer
        ]
    except Exception:
        return []

    results: List[NameserverInfo] = []
    for host in sorted(set(ns_hosts)):
        addresses: List[str] = []
        try:
            a_records = _query_resolver(resolver, host, "A")
            addresses.extend(
                record.address if hasattr(record, "address") else str(record)
                for record in a_records
            )
        except Exception:
            pass

        try:
            aaaa_records = _query_resolver(resolver, host, "AAAA")
            addresses.extend(
                record.address if hasattr(record, "address") else str(record)
                for record in aaaa_records
            )
        except Exception:
            pass

        whois_info = None
        lookup_targets = [host, host.split(".", 1)[-1], domain]
        lookup_targets.extend(addresses)
        for candidate in lookup_targets:
            whois_info = _collect_whois_via_cli(candidate)
            if whois_info and (whois_info.descr or whois_info.country):
                break

        results.append(
            NameserverInfo(
                host=host,
                addresses=sorted(set(addresses)),
                descr=whois_info.descr if whois_info else None,
                country=whois_info.country if whois_info else None,
            )
        )

    return results


def _collect_whois_via_cli(domain: str) -> Optional[RegistrarInfo]:
    try:
        completed = subprocess.run(
            ["whois", domain],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    if not completed.stdout and not completed.stderr:
        return None

    raw_text = "\n".join(part for part in [completed.stdout, completed.stderr] if part)
    parsed = _extract_from_raw(raw_text)
    if parsed.registrar or parsed.source or parsed.country or parsed.record_maintained_by:
        return parsed
    return None


def collect_dns_report(hostname: str) -> DnsReport:
    domain = _first_ns_domain(hostname)
    warnings: List[str] = []

    registrar = RegistrarInfo()
    try:
        import whois  # type: ignore

        whois_data = whois.whois(domain)
        registrar.registrar = _to_scalar(getattr(whois_data, "registrar", None) or whois_data.get("registrar"))
        registrar.country = _to_scalar(getattr(whois_data, "country", None) or whois_data.get("country"))
        registrar.source = _to_scalar(getattr(whois_data, "source", None) or whois_data.get("source"))
        registrar.record_maintained_by = _to_scalar(
            getattr(whois_data, "record_maintained_by", None) or whois_data.get("record_maintained_by")
        )

        raw_text = getattr(whois_data, "text", None) or whois_data.get("text") or ""
        parsed = _extract_from_raw(raw_text if isinstance(raw_text, str) else "")

        if not registrar.registrar:
            registrar.registrar = parsed.registrar
        if not registrar.source:
            registrar.source = parsed.source
        if not registrar.country:
            registrar.country = parsed.country
        if not registrar.record_maintained_by:
            registrar.record_maintained_by = parsed.record_maintained_by

    except Exception:
        cli_whois = _collect_whois_via_cli(domain)
        if cli_whois:
            registrar = cli_whois
        else:
            warnings.append("WHOIS lookup unavailable; registrar metadata unavailable")

    if not registrar.record_maintained_by:
        cli_whois = _collect_whois_via_cli(domain)
        if cli_whois:
            registrar.record_maintained_by = cli_whois.record_maintained_by
            if not registrar.registrar:
                registrar.registrar = cli_whois.registrar
            if not registrar.source:
                registrar.source = cli_whois.source
            if not registrar.country:
                registrar.country = cli_whois.country

    nameservers = _resolve_nameservers(domain)
    if not nameservers:
        warnings.append("authoritative nameserver lookup returned no NS records")

    return DnsReport(domain=domain, registrar=registrar, nameservers=nameservers, warnings=warnings)


def display_dns_report(hostname: str, compact: bool = False) -> None:
    report = collect_dns_report(hostname)

    if compact:
        print(" [Registrar]")
        print(f"  - registrar : {report.registrar.registrar or 'N/A'}")
        print(f"  - record maintained by : {report.registrar.record_maintained_by or 'N/A'}")
        print(f"  - source    : {report.registrar.source or 'N/A'}")
        print(f"  - country   : {report.registrar.country or 'N/A'}")

        print("\n [Authoritative Nameservers]")
        if report.nameservers:
            for ns in report.nameservers:
                parts = [ns.host.rstrip(".")]
                if ns.descr:
                    parts.append(f"descr: {ns.descr}")
                if ns.country:
                    parts.append(f"country: {ns.country}")
                print(f"  - {' | '.join(parts)}")
        else:
            print("  - N/A")
        return

    print("\n" + "=" * 60)
    print(f" DNS Summary for: {hostname}")
    print("=" * 60)
    print(f"Domain used      : {report.domain}")

    print("\n [Registrar]")
    print(f"  - registrar : {report.registrar.registrar or 'N/A'}")
    print(
        f"  - record maintained by : {report.registrar.record_maintained_by or 'N/A'}"
    )
    print(f"  - source    : {report.registrar.source or 'N/A'}")
    print(f"  - country   : {report.registrar.country or 'N/A'}")

    print("\n [Authoritative Nameservers]")
    if report.nameservers:
        for ns in report.nameservers:
            joined_ips = ", ".join(ns.addresses) if ns.addresses else "N/A"
            descr = f" | descr: {ns.descr}" if ns.descr else ""
            country = f" | country: {ns.country}" if ns.country else ""
            print(f"  - {ns.host}: {joined_ips}{descr}{country}")
    else:
        print("  - N/A")

    if report.warnings:
        print("\n [DNS Warnings]")
        for warning in report.warnings:
            print(f"  - {warning}")

    print("=" * 60)
