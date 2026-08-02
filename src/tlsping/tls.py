from __future__ import annotations

import socket
import ssl
import sys
import urllib.request
from typing import Any, Dict, Optional, Tuple

TRACE_ENABLED = False


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


def format_name_attributes(name) -> str:
    parts = []
    for attr in name:
        parts.append(f"{attr.oid._name}={attr.value}")
    return ", ".join(parts)


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


def get_tls_certificate(
    hostname: str,
    port: int,
    starttls: Optional[str] = None,
) -> Tuple[Optional[bytes], Optional[Dict[str, Any]], Optional[str], Optional[Tuple[str, str, int]]]:
    """
    Connects to hostname:port, executes TLS ClientHello, and returns
    the raw DER-encoded certificate and decoded metadata.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

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

            return der_cert, tls_sock.getpeercert(binary_form=False), tls_version, cipher_used

    raise RuntimeError("TLS handshake did not produce certificate data")


def display_cert_info(
    hostname: str,
    port: int,
    der_cert: bytes,
    cert_dict: Dict[str, Any],
    tls_ver: str,
    cipher: Tuple[str, str, int],
    starttls: Optional[str] = None,
):
    """Prints formatted certificate and CA details."""
    print("=" * 60)
    print(f" TLS Handshake Summary for: {hostname}:{port}")
    print("=" * 60)
    print(f"Protocol Version : {tls_ver}")
    print(f"Cipher Suite     : {cipher[0]} ({cipher[1]} bits)")
    print("-" * 60)

    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        cert = x509.load_der_x509_certificate(der_cert, default_backend())

        print(" [Subject Details]")
        for attr in cert.subject:
            print(f"  - {attr.oid._name}: {attr.value}")

        print("\n [Certificate Authority / Issuer]")
        chain = build_certificate_chain(cert)
        issuer_name = cert.issuer
        if len(chain) > 1:
            issuer_name = chain[-1].subject
        for attr in issuer_name:
            print(f"  - {attr.oid._name}: {attr.value}")

        print("\n [Validity Period]")
        print(f"  - Not Before : {cert.not_valid_before.isoformat()}")
        print(f"  - Not After  : {cert.not_valid_after.isoformat()}")

        try:
            san = cert.extensions.get_extension_for_oid(x509.OID_SUBJECT_ALTERNATIVE_NAME)
            names = san.value.get_values_for_type(x509.DNSName)
            print(f"\n [SAN Domains] ({len(names)} found):")
            print(f"  - {', '.join(names[:5])}" + ("..." if len(names) > 5 else ""))
        except Exception:
            pass

        chain = build_certificate_chain(cert)
        if len(chain) > 1:
            print("\n [Certificate Chain]")
            for index, chain_cert in enumerate(chain):
                label = "Leaf" if index == 0 else (
                    "Root" if index == len(chain) - 1 and is_self_signed(chain_cert) else f"CA-{index}"
                )
                print(f"  - {label}")
                print(f"    * Subject: {format_name_attributes(chain_cert.subject)}")
                print(f"    * Issuer : {format_name_attributes(chain_cert.issuer)}")
                try:
                    aia = chain_cert.extensions.get_extension_for_oid(x509.OID_AUTHORITY_INFORMATION_ACCESS).value
                    ca_issuers = [
                        desc.access_location.value
                        for desc in aia
                        if desc.access_method.dotted_string == "1.3.6.1.5.5.7.48.2"
                    ]
                    if ca_issuers:
                        print(f"    * CA Issuers URLs: {', '.join(ca_issuers)}")
                except Exception:
                    pass

                subject_country = [attr.value for attr in chain_cert.subject if attr.oid._name == "countryName"]
                subject_org = [attr.value for attr in chain_cert.subject if attr.oid._name == "organizationName"]
                if subject_country or subject_org:
                    print(
                        "    * Subject location/org: "
                        f"country={subject_country[0] if subject_country else 'N/A'}, "
                        f"org={subject_org[0] if subject_org else 'N/A'}"
                    )

        trust_ok, trust_reason = assess_os_trust(hostname, port, starttls=starttls)
        print("\n [OS Trust]")
        if trust_ok:
            print("  - trustable by OS: yes")
        else:
            print("  - trustable by OS: no")
            if trust_reason:
                print(f"  - reason: {trust_reason}")

    except ImportError:
        print(" (Note: Install 'cryptography' for full details: pip install cryptography)\n")
        subject = parse_tuple_dict(cert_dict.get("subject", ()))
        issuer = parse_tuple_dict(cert_dict.get("issuer", ()))

        print(" [Subject]")
        print(f"  - Common Name : {subject.get('commonName', 'N/A')}")
        print(f"  - Organization: {subject.get('organizationName', 'N/A')}")

        print("\n [Certificate Authority / Issuer]")
        print(f"  - Common Name : {issuer.get('commonName', 'N/A')}")
        print(f"  - Organization: {issuer.get('organizationName', 'N/A')}")

        print("\n [Validity Period]")
        print(f"  - Expires On  : {cert_dict.get('notAfter')}")

    print("=" * 60)
