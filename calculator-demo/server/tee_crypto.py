"""Crypto helpers shared by the server (inside the TEE) and the client (outside).

Scheme (a tiny "attested ECIES"):
  1. The server holds a P-256 key pair whose private key is derived by the TEE's
     KMS (Tappd.DeriveKey). It never leaves the enclave.
  2. The server asks the TEE for a TDX quote whose 64-byte report_data field is
     sha256(server_public_key) || 32 zero bytes. The quote is signed by the CPU
     (on real hardware), so it binds "this public key" to "this exact code".
  3. For each request the client makes a fresh ephemeral P-256 key, does ECDH
     with the server's attested public key, and runs HKDF-SHA256 to get a
     one-time AES-256-GCM key. Both sides compute the same key; nobody on the
     wire can.
  4. The request and the response are each sealed with AES-256-GCM (random
     12-byte nonce, the client's ephemeral public key as associated data).
"""

import hashlib
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HKDF_INFO = b"phala-calc-demo/v1 aes-256-gcm"


def pub_bytes(pub: ec.EllipticCurvePublicKey) -> bytes:
    """Uncompressed SEC1 encoding (65 bytes, starts with 0x04)."""
    return pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def load_pub(raw: bytes) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)


def new_ephemeral() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def ecdh_shared_secret(priv: ec.EllipticCurvePrivateKey, peer_pub: ec.EllipticCurvePublicKey) -> bytes:
    return priv.exchange(ec.ECDH(), peer_pub)


def session_key(shared_secret: bytes, client_pub_raw: bytes, server_pub_raw: bytes) -> bytes:
    """HKDF-SHA256 over the ECDH secret, salted with both public keys."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hashlib.sha256(client_pub_raw + server_pub_raw).digest(),
        info=HKDF_INFO,
    ).derive(shared_secret)


def seal(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def open_(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, aad)  # raises InvalidTag if tampered


def report_data_for(server_pub_raw: bytes) -> bytes:
    """What the server puts in the quote: sha256(pubkey) padded to 64 bytes."""
    return hashlib.sha256(server_pub_raw).digest() + b"\x00" * 32


# --- TDX quote v4 parsing (just the fields we care about) -------------------
# Layout: 48-byte header, then a 584-byte TD report body, then the signature.
_HEADER = 48
_BODY_FIELDS = [  # (name, size) in order
    ("tee_tcb_svn", 16), ("mr_seam", 48), ("mr_signer_seam", 48),
    ("seam_attributes", 8), ("td_attributes", 8), ("xfam", 8),
    ("mr_td", 48), ("mr_config_id", 48), ("mr_owner", 48), ("mr_owner_config", 48),
    ("rtmr0", 48), ("rtmr1", 48), ("rtmr2", 48), ("rtmr3", 48),
    ("report_data", 64),
]


def parse_tdx_quote(quote: bytes) -> dict:
    out = {
        "version": int.from_bytes(quote[0:2], "little"),
        "att_key_type": int.from_bytes(quote[2:4], "little"),
        "tee_type": hex(int.from_bytes(quote[4:8], "little")),  # 0x81 = TDX
    }
    off = _HEADER
    for name, size in _BODY_FIELDS:
        out[name] = quote[off:off + size].hex()
        off += size
    out["signature_section_bytes"] = len(quote) - off
    return out


def short(b: bytes | str, n: int = 16) -> str:
    h = b.hex() if isinstance(b, (bytes, bytearray)) else b
    return h if len(h) <= 2 * n else f"{h[:n]}...{h[-8:]} ({len(h) // 2} bytes)"
