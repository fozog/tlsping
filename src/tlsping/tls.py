from __future__ import annotations

import socket
import ssl
import sys
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

TRACE_ENABLED = False


@dataclass(frozen=True)
class TLSProbeResult:
    hostname: str
    port: int
    der_cert: bytes
    cert_dict: Dict[str, Any]
    tls_version: str
    cipher: Tuple[str, str, int]
    cert_chain: List[Any]
    os_trust_ok: bool
    os_trust_reason: Optional[str]


def set_trace_enabled(enabled: bool) -> None:
    global TRACE_ENABLED
    TRACE_ENABLED = enabled


def trace(message: str) -> None:
    if not TRACE_ENABLED:
        return
    print(f"[TRACE] {message}", file=sys.stderr, flush=True)


def parse_tuple_dict(tuples):
    """Utility to flatten Python's ssl certificate tuple structures."""
    out = {}
    for item in tuples:
        for key, val in item:
            out[key] = val
    return out


def format_name_attributes(name) -> str:
    parts = []
    for attr in name:
        parts.append(f"{attr.oid._name}={attr.value}")
    return ", ".join(parts)


def _priority_name_from_subject(subject) -> str:
    # Priority agreed for issuer/name display: OU > Organization > Common Name.
    name_fields = ["organizationalUnitName", "organizationName", "commonName"]
    for field_name in name_fields:
        values = [attr.value for attr in subject if attr.oid._name == field_name]
        if values:
            return values[0]
    return "N/A"


def chain_entry_country_name_to_string(chain_cert) -> str:
    subject = chain_cert.subject
    country_values = [attr.value for attr in subject if attr.oid._name == "countryName"]
    country = country_values[0] if country_values else "N/A"
    name = _priority_name_from_subject(subject)
    return f"{country}:{name}"


def chain_to_string(result: TLSProbeResult) -> str:
    if len(result.cert_chain) <= 1:
        return ""
    entries = [chain_entry_country_name_to_string(chain_cert) for chain_cert in result.cert_chain[1:]]
    return " > ".join(entries)


def root_to_string(result: TLSProbeResult) -> str:
    if not result.cert_chain:
        return ""
    return chain_entry_country_name_to_string(result.cert_chain[-1])


def full_chain_to_string(result: TLSProbeResult) -> str:
    lines: List[str] = []
    lines.append("[TLS]")
    lines.append(f" - Protocol Version : {result.tls_version}")
    lines.append(f" - Cipher Suite     : {result.cipher[0]} ({result.cipher[1]} bits)")

    try:
        lines.append("")
        lines.append("[Certificate Chain]")
        for index, chain_cert in enumerate(result.cert_chain):
            label = "Leaf" if index == 0 else (
                "Root" if index == len(result.cert_chain) - 1 and chain_cert.subject == chain_cert.issuer else f"CA-{index}"
            )
            lines.append(f"  - {label}")
            lines.append(f"    * Subject: {format_name_attributes(chain_cert.subject)}")
            lines.append(f"    * Issuer : {format_name_attributes(chain_cert.issuer)}")
            lines.append(f"    * Validity: {chain_cert.not_valid_before.isoformat()} - {chain_cert.not_valid_after.isoformat()}")
            try:
                from cryptography import x509

                aia = chain_cert.extensions.get_extension_for_oid(x509.OID_AUTHORITY_INFORMATION_ACCESS).value
                ca_issuers = [
                    desc.access_location.value
                    for desc in aia
                    if desc.access_method.dotted_string == "1.3.6.1.5.5.7.48.2"
                ]
                if ca_issuers:
                    lines.append(f"    * CA Issuers URLs: {', '.join(ca_issuers)}")
            except Exception:
                pass

            try:
                from cryptography import x509

                san = chain_cert.extensions.get_extension_for_oid(x509.OID_SUBJECT_ALTERNATIVE_NAME)
                names = san.value.get_values_for_type(x509.DNSName)
                lines.append(f"    * SAN Domain(s):  {', '.join(names[:5])}" + ("..." if len(names) > 5 else ""))

            except Exception:
                pass


            subject_country = [attr.value for attr in chain_cert.subject if attr.oid._name == "countryName"]
            subject_org = [attr.value for attr in chain_cert.subject if attr.oid._name == "organizationName"]
            if subject_country or subject_org:
                lines.append(
                    "    * Subject location/org: "
                    f"country={subject_country[0] if subject_country else 'N/A'}, "
                    f"org={subject_org[0] if subject_org else 'N/A'}"
                )

        lines.append("")
        lines.append("[OS Trust]")
        if result.os_trust_ok:
            lines.append("  - trustable by OS: yes")
        else:
            lines.append("  - trustable by OS: no")
            if result.os_trust_reason:
                lines.append(f"  - reason: {result.os_trust_reason}")

    except IndexError:
        lines.append(" (Note: Install 'cryptography' for full details: pip install cryptography)")
        lines.append("")
        subject = parse_tuple_dict(result.cert_dict.get("subject", ()))
        issuer = parse_tuple_dict(result.cert_dict.get("issuer", ()))

        lines.append(" [Subject]")
        lines.append(f"  - Common Name : {subject.get('commonName', 'N/A')}")
        lines.append(f"  - Organization: {subject.get('organizationName', 'N/A')}")

        lines.append("")
        lines.append(" [Certificate Authority / Issuer]")
        lines.append(f"  - Common Name : {issuer.get('commonName', 'N/A')}")
        lines.append(f"  - Organization: {issuer.get('organizationName', 'N/A')}")

        lines.append("")
        lines.append(" [Validity Period]")
        lines.append(f"  - Expires On  : {result.cert_dict.get('notAfter')}")

    return "\n".join(lines) + "\n"


def dump_client_hello_info(hostname: str, port: int, context: ssl.SSLContext) -> None:
    ciphers = context.get_ciphers()
    cipher_names = ", ".join(cipher["name"] for cipher in ciphers[:8])
    if len(ciphers) > 8:
        cipher_names += f", ... ({len(ciphers)} total)"

    trace(f"ClientHello target: {hostname}:{port}")
    trace(f"ClientHello SNI: {hostname}")
    trace(f"ClientHello min_version: {context.minimum_version}")
    trace(f"ClientHello max_version: {context.maximum_version}")
    trace(f"ClientHello check_hostname: {context.check_hostname}")
    trace(f"ClientHello verify_mode: {context.verify_mode}")
    trace(f"ClientHello offered ciphers: {cipher_names}")


def load_x509_certificate_from_bytes(data: bytes):
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    if data.lstrip().startswith(b"-----BEGIN"):
        return x509.load_pem_x509_certificate(data, default_backend())
    return x509.load_der_x509_certificate(data, default_backend())


def fetch_issuer_certificate(cert):
    from cryptography import x509
    from cryptography.x509.oid import AuthorityInformationAccessOID

    try:
        aia = cert.extensions.get_extension_for_oid(x509.OID_AUTHORITY_INFORMATION_ACCESS).value
    except x509.ExtensionNotFound:
        return None

    for access_desc in aia:
        if access_desc.access_method != AuthorityInformationAccessOID.CA_ISSUERS:
            continue

        url = access_desc.access_location.value
        trace(f"CA Issuers URL: {url}")

        try:
            with urllib.request.urlopen(url, timeout=10) as response:
                issuer_bytes = response.read()
            return load_x509_certificate_from_bytes(issuer_bytes)
        except Exception as exc:
            trace(f"failed to fetch issuer certificate from {url}: {exc}")

    return None


def assess_os_trust(hostname: str, port: int, starttls: Optional[str] = None) -> tuple[bool, Optional[str]]:
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    trace(f"assessing OS trust for {hostname}:{port}")

    try:
        with socket.create_connection((hostname, port), timeout=10) as raw_sock:
            if starttls == "SMTP":
                trace("OS trust check: trying STARTTLS")
                raw_sock.recv(1024)
                raw_sock.sendall(b"EHLO tls-ping.local\r\n")
                raw_sock.recv(2048)
                raw_sock.sendall(b"STARTTLS\r\n")
                starttls_resp = raw_sock.recv(1024)
                if not starttls_resp.startswith(b"220"):
                    return False, f"STARTTLS failed during trust check: {starttls_resp.decode().strip()}"

            with context.wrap_socket(raw_sock, server_hostname=hostname) as tls_sock:
                trace(f"OS trust check TLS version: {tls_sock.version()}")
                trace(f"OS trust check cipher: {tls_sock.cipher()}")
                return True, None

    except ssl.SSLCertVerificationError as exc:
        return False, f"certificate verification failed: {exc}"
    except ssl.SSLError as exc:
        return False, f"TLS error during trust check: {exc}"
    except OSError as exc:
        return False, f"network error during trust check: {exc}"



def is_self_signed(cert) -> bool:
    return cert.subject == cert.issuer


def build_certificate_chain(leaf_cert):
    chain = [leaf_cert]
    current_cert = leaf_cert

    while not is_self_signed(current_cert):
        issuer_cert = fetch_issuer_certificate(current_cert)
        if issuer_cert is None:
            break

        if any(existing.subject == issuer_cert.subject for existing in chain):
            trace(f"stopping chain walk on repeated subject: {issuer_cert.subject.rfc4514_string()}")
            break

        chain.append(issuer_cert)
        current_cert = issuer_cert

    return chain


def get_tls_certificate(
    hostname: str,
    port: int,
    starttls: Optional[str] = None,
) -> TLSProbeResult:
    """
    Connects to hostname:port, executes TLS ClientHello, and returns
    the raw DER-encoded certificate and decoded metadata.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    if TRACE_ENABLED:
        dump_client_hello_info(hostname, port, context)

    trace(f"resolving addresses for {hostname}:{port}")
    resolved_addresses = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    for family, _socktype, _proto, _canonname, sockaddr in resolved_addresses:
        try:
            family_name = socket.AddressFamily(family).name
        except ValueError:
            family_name = str(family)
        trace(f"resolved candidate: family={family_name}, sockaddr={sockaddr}")

    trace(f"connecting to {hostname}:{port}")
    with socket.create_connection((hostname, port), timeout=10) as raw_sock:
        trace("connection established")
        try:
            family_name = socket.AddressFamily(raw_sock.family).name
        except ValueError:
            family_name = str(raw_sock.family)
        trace(f"connected socket family: {family_name}, peer: {raw_sock.getpeername()}")

        if starttls == "SMTP":
            trace("trying STARTTLS")
            raw_sock.recv(1024)
            raw_sock.sendall(b"EHLO tls-ping.local\r\n")
            raw_sock.recv(2048)
            raw_sock.sendall(b"STARTTLS\r\n")
            starttls_resp = raw_sock.recv(1024)
            if not starttls_resp.startswith(b"220"):
                raise RuntimeError(f"STARTTLS failed: {starttls_resp.decode().strip()}")

        trace("trying client hello")

        with context.wrap_socket(raw_sock, server_hostname=hostname, do_handshake_on_connect=False) as tls_sock:
            trace("client hello received")
            trace("starting TLS handshake")
            try:
                tls_sock.do_handshake()
            except TimeoutError as exc:
                trace("TLS handshake timed out")
                raise RuntimeError("TLS handshake timed out before certificate retrieval") from exc
            trace("TLS handshake completed")

            trace("trying to get certificate")
            der_cert = tls_sock.getpeercert(binary_form=True)
            trace("certificate obtained")
            cipher_used = tls_sock.cipher()
            tls_version = tls_sock.version()

            cert_dict = tls_sock.getpeercert(binary_form=False)

            cert_chain: List[Any] = []
            try:
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend

                leaf_cert = x509.load_der_x509_certificate(der_cert, default_backend())
                cert_chain = build_certificate_chain(leaf_cert)
            except ImportError:
                trace("cryptography unavailable while building certificate chain")
            except Exception as exc:
                trace(f"failed to build certificate chain: {exc}")

            trust_ok, trust_reason = assess_os_trust(hostname, port, starttls=starttls)

            return TLSProbeResult(
                hostname=hostname,
                port=port,
                der_cert=der_cert,
                cert_dict=cert_dict,
                tls_version=tls_version,
                cipher=cipher_used,
                cert_chain=cert_chain,
                os_trust_ok=trust_ok,
                os_trust_reason=trust_reason,
            )

    raise RuntimeError("TLS handshake did not produce certificate data")
