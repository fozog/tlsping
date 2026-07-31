from __future__ import annotations

import argparse
from typing import Optional

from .dns import display_dns_report
from .tls import display_cert_info, get_tls_certificate, set_trace_enabled, trace

# Standard protocol port mappings
PROTOCOL_PORTS = {
    "HTTPS": 443,
    "NTS-KE": 4460,  # Network Time Security Key Establishment
    "SMTP": 587,  # Explicit TLS (STARTTLS)
    "SMTPS": 465,  # Implicit TLS
    "IMAP": 993,
    "POP3": 995,
}


def resolve_port_spec(port_spec: Optional[str]) -> tuple[int, Optional[str]]:
    if port_spec is None:
        return 443, None

    upper_spec = port_spec.upper()
    if upper_spec in PROTOCOL_PORTS:
        starttls_mode = "SMTP" if upper_spec == "SMTP" else None
        return PROTOCOL_PORTS[upper_spec], starttls_mode

    if port_spec.isdigit():
        return int(port_spec), None

    valid = ", ".join(sorted(PROTOCOL_PORTS))
    raise ValueError(f"Unknown port/protocol '{port_spec}'. Use an integer or one of: {valid}")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Fetch and display TLS and DNS details for a host.")
    parser.add_argument(
        "hostname",
        help="Target hostname, for example github.com or gbg2-ts.nts.netnod.se",
    )
    parser.add_argument(
        "--port",
        dest="port_spec",
        metavar="[<port>|<NTS-KE>|<HTTPS>|<SMTP>|<SMTPS>|<IMAP>|<POP3>]",
        default="HTTPS",
        help="Port number or protocol alias. Defaults to HTTPS. This probe is TCP/TLS only; no UDP support.",
    )
    parser.add_argument(
        "--trace",
        action="store_true",
        help="Print trace logs while resolving and connecting.",
    )
    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    set_trace_enabled(args.trace)

    try:
        port, starttls_mode = resolve_port_spec(args.port_spec)
    except ValueError as exc:
        parser.error(str(exc))

    try:
        der, cert_dict, tls_ver, cipher = get_tls_certificate(args.hostname, port, starttls=starttls_mode)

        if der is None or cert_dict is None or tls_ver is None or cipher is None:
            raise RuntimeError("TLS certificate retrieval did not return complete data")

        display_cert_info(args.hostname, port, der, cert_dict, tls_ver, cipher, starttls=starttls_mode)
    except Exception as exc:
        print(f"\n[ERROR] Failed to retrieve TLS certificate: {exc}")

    try:
        display_dns_report(args.hostname)
    except Exception as exc:
        trace(f"DNS summary failed: {exc}")
        print(f"\n[WARN] Failed to collect DNS summary: {exc}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
