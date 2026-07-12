"""Generate a self-signed CA and a server certificate signed by that CA.

Usage:
    python gen_certs.py [--hostname localhost] [--out-dir certs]

After running this, import certs/ca.crt into your OS/browser trust store so
that clients (including the `zed` binary and your browser) trust the server
certificate served by server.py.
"""

import argparse
import datetime
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def make_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def write_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def write_cert(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--hostname",
        default="localhost",
        help="Hostname the server certificate should be valid for (default: localhost)",
    )
    parser.add_argument(
        "--out-dir",
        default="certs",
        help="Directory to write generated keys/certs into (default: ./certs)",
    )
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    now = datetime.datetime.now(datetime.timezone.utc)

    # --- Certificate Authority ---
    ca_key = make_key()
    ca_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Zed Auth Server Local CA")]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    write_key(out_dir / "ca.key", ca_key)
    write_cert(out_dir / "ca.crt", ca_cert)

    # --- Server certificate, signed by the CA above ---
    server_key = make_key()
    server_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, args.hostname)]
    )

    san_entries: list[x509.GeneralName] = [x509.DNSName(args.hostname)]
    if args.hostname != "localhost":
        san_entries.append(x509.DNSName("localhost"))
    try:
        san_entries.append(x509.IPAddress(ipaddress.ip_address(args.hostname)))
    except ValueError:
        pass
    san_entries.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))

    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    write_key(out_dir / "server.key", server_key)
    write_cert(out_dir / "server.crt", server_cert)

    print(f"Wrote CA key/cert and server key/cert to {out_dir}/")
    print(f"Server certificate is valid for: {args.hostname}, localhost, 127.0.0.1")
    print()
    print("Next steps:")
    print(f"  1. Trust {out_dir / 'ca.crt'} in your OS trust store (see README instructions).")
    print("  2. Run: python server.py")


if __name__ == "__main__":
    main()
