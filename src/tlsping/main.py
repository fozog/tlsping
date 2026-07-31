from __future__ import annotations

import argparse
import socket
import ssl
import sys
import urllib.request
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

# Standard protocol port mappings
PROTOCOL_PORTS = {
    "HTTPS": 443,
    "NTS-KE": 4460,  # Network Time Security Key Establishment
    "SMTP": 587,     # Explicit TLS (STARTTLS)
    "SMTPS": 465,    # Implicit TLS
    "IMAP": 993,
    "POP3": 995,
}

TRACE_ENABLED = False


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


def set_trace_enabled(enabled: bool) -> None:
    global TRACE_ENABLED
    TRACE_ENABLED = enabled

def parse_tuple_dict(tuples):
    """Utility to flatten Python's ssl certificate tuple structures."""
    out = {}
    for item in tuples:
        for key, val in item:
            out[key] = val
    return out


def trace(message: str) -> None:
    if not TRACE_ENABLED:
        return
    print(f"[TRACE] {message}", file=sys.stderr, flush=True)


def load_x509_certificate_from_bytes(data: bytes):
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    if data.lstrip().startswith(b"-----BEGIN"):
        return x509.load_pem_x509_certificate(data, default_backend())
    return x509.load_der_x509_certificate(data, default_backend())


def fetch_issuer_certificate(cert) :
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
                banner = raw_sock.recv(1024)
                raw_sock.sendall(b"EHLO tls-ping.local\r\n")
                ehlo_resp = raw_sock.recv(2048)
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
    # Disable strict hostname verification if you want to inspect invalid/expired certs
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    dump_client_hello_info(hostname, port, context)

    trace(f"resolving addresses for {hostname}:{port}")
    resolved_addresses = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    for family, socktype, proto, canonname, sockaddr in resolved_addresses:
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
        
        # Handle STARTTLS protocols before TLS wrapping
        if starttls == "SMTP":
            trace("trying STARTTLS")
            banner = raw_sock.recv(1024)
            raw_sock.sendall(b"EHLO tls-ping.local\r\n")
            ehlo_resp = raw_sock.recv(2048)
            raw_sock.sendall(b"STARTTLS\r\n")
            starttls_resp = raw_sock.recv(1024)
            if not starttls_resp.startswith(b"220"):
                raise RuntimeError(f"STARTTLS failed: {starttls_resp.decode().strip()}")

        trace("trying client hello")

        # Wrap raw socket in TLS layer (triggers ClientHello -> ServerHello)
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

            # Binary DER format allows deep parsing with cryptography library
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
):
    """Prints formatted certificate and CA details."""
    print("=" * 60)
    print(f" TLS Handshake Summary for: {hostname}:{port}")
    print("=" * 60)
    print(f"Protocol Version : {tls_ver}")
    print(f"Cipher Suite     : {cipher[0]} ({cipher[1]} bits)")
    print("-" * 60)

    try:
        # Preferred method using cryptography package for detailed X.509 parsing
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        cert = x509.load_der_x509_certificate(der_cert, default_backend())

        print(" [Subject Details]")
        for attr in cert.subject:
            print(f"  - {attr.oid._name}: {attr.value}")

        print("\n [Certificate Authority / Issuer]")
        for attr in cert.issuer:
            print(f"  - {attr.oid._name}: {attr.value}")

        print("\n [Validity Period]")
        print(f"  - Not Before : {cert.not_valid_before.isoformat()}")
        print(f"  - Not After  : {cert.not_valid_after.isoformat()}")

        # Check for Subject Alternative Names (SAN)
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
                label = "Leaf" if index == 0 else ("Root" if index == len(chain) - 1 and is_self_signed(chain_cert) else f"CA-{index}")
                print(f"  - {label}")
                print(f"    * Subject: {format_name_attributes(chain_cert.subject)}")
                print(f"    * Issuer : {format_name_attributes(chain_cert.issuer)}")
                try:
                    aia = chain_cert.extensions.get_extension_for_oid(x509.OID_AUTHORITY_INFORMATION_ACCESS).value
                    ca_issuers = [desc.access_location.value for desc in aia if desc.access_method.dotted_string == '1.3.6.1.5.5.7.48.2']
                    if ca_issuers:
                        print(f"    * CA Issuers URLs: {', '.join(ca_issuers)}")
                except Exception:
                    pass

                subject_country = [attr.value for attr in chain_cert.subject if attr.oid._name == 'countryName']
                subject_org = [attr.value for attr in chain_cert.subject if attr.oid._name == 'organizationName']
                if subject_country or subject_org:
                    print(f"    * Subject location/org: country={subject_country[0] if subject_country else 'N/A'}, org={subject_org[0] if subject_org else 'N/A'}")

        trust_ok, trust_reason = assess_os_trust(hostname, port)
        print("\n [OS Trust]")
        if trust_ok:
            print("  - trustable by OS: yes")
        else:
            print("  - trustable by OS: no")
            if trust_reason:
                print(f"  - reason: {trust_reason}")


    except ImportError:
        # Fallback using standard library ssl parser
        print(" (Note: Install 'cryptography' for full details: pip install cryptography)\n")
        subject = parse_tuple_dict(cert_dict.get('subject', ()))
        issuer = parse_tuple_dict(cert_dict.get('issuer', ()))

        print(" [Subject]")
        print(f"  - Common Name : {subject.get('commonName', 'N/A')}")
        print(f"  - Organization: {subject.get('organizationName', 'N/A')}")

        print("\n [Certificate Authority / Issuer]")
        print(f"  - Common Name : {issuer.get('commonName', 'N/A')}")
        print(f"  - Organization: {issuer.get('organizationName', 'N/A')}")

        print("\n [Validity Period]")
        print(f"  - Expires On  : {cert_dict.get('notAfter')}")

    print("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch and display TLS certificate details for a host.")
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

        display_cert_info(args.hostname, port, der, cert_dict, tls_ver, cipher)
    except Exception as e:
        print(f"\n[ERROR] Failed to retrieve TLS certificate: {e}")