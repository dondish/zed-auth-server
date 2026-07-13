"""Crypto helpers — must stay byte-compatible with crates/rpc/src/auth.rs."""

import base64
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * ((-len(s)) % 4))


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def parse_pkcs1_der_public_key(der: bytes) -> rsa.RSAPublicKey:
    """Parse a raw PKCS#1 RSAPublicKey DER blob: SEQUENCE { INTEGER n, INTEGER e }.

    Zed's Rust client serializes its public key with `to_pkcs1_der()`, which is
    NOT the SubjectPublicKeyInfo format Python's `load_der_public_key` expects,
    so we parse the two integers by hand.
    """

    def read_tlv(data: bytes, idx: int) -> tuple[int, bytes, int]:
        tag = data[idx]
        idx += 1
        length = data[idx]
        idx += 1
        if length & 0x80:
            num_len_bytes = length & 0x7F
            length = int.from_bytes(data[idx : idx + num_len_bytes], "big")
            idx += num_len_bytes
        return tag, data[idx : idx + length], idx + length

    tag, seq, _ = read_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("expected SEQUENCE in PKCS#1 public key DER")
    tag, n_bytes, next_idx = read_tlv(seq, 0)
    if tag != 0x02:
        raise ValueError("expected INTEGER (modulus)")
    tag, e_bytes, _ = read_tlv(seq, next_idx)
    if tag != 0x02:
        raise ValueError("expected INTEGER (exponent)")
    return rsa.RSAPublicNumbers(
        int.from_bytes(e_bytes, "big"), int.from_bytes(n_bytes, "big")
    ).public_key()


def random_access_token() -> str:
    # Matches Zed's `rpc::auth::random_token`: 48 random bytes, base64url (64 chars).
    return b64url_encode(os.urandom(48))


def encrypt_for_client(public_key: rsa.RSAPublicKey, token: str) -> str:
    # Matches Zed's EncryptionFormat::V1: RSA-OAEP, SHA-256 digest + MGF1(SHA-256).
    return b64url_encode(
        public_key.encrypt(
            token.encode("utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    )
