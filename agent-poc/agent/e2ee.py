"""Phala ACI end-to-end encryption, version 2, X25519 suite (spec: Dstack-TEE/private-ai-gateway spec/e2ee-v2.md).

Every content field of the request is encrypted to the gateway's attested E2EE public key; every content field of the
response comes back encrypted to our one-time client key. Each field gets its own ephemeral key and AES-GCM nonce:

  shared  = X25519(ephemeral_private, peer_public)
  key     = HKDF-SHA256(salt=none, ikm=shared, info="aci.e2ee.v2.x25519", length=32)
  aad     = JCS({"purpose", "algo", "model", "field", "nonce", "ts"[, "id"]})
  blob    = hex( ephemeral_public(32) || aes_nonce(12) || AES-256-GCM(key, aes_nonce, plaintext, aad) )

For the Inspector, every intermediate value is recorded in a trace (one-time keys only, never long-term keys).
"""

import os

import rfc8785
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ALGO = "x25519-aes-256-gcm-hkdf-sha256"
INFO = b"aci.e2ee.v2.x25519"


def _raw(pub: X25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _priv_raw(priv: X25519PrivateKey) -> bytes:
    return priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())


def derive(shared: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=INFO).derive(shared)


def aad(purpose: str, model: str, field: str, nonce: str, ts: int, resp_id: str | None = None) -> bytes:
    d = {"purpose": purpose, "algo": ALGO, "model": model, "field": field, "nonce": nonce, "ts": ts}
    if resp_id is not None:
        d["id"] = resp_id
    return rfc8785.dumps(d)


def encrypt_field(peer_pub_hex: str, plaintext: str, aad_bytes: bytes,
                  eph: X25519PrivateKey | None = None, aes_nonce: bytes | None = None) -> tuple[str, dict]:
    """Encrypt one field. eph/aes_nonce can be passed in to re-create a ciphertext deterministically (verifier)."""
    eph = eph or X25519PrivateKey.generate()
    aes_nonce = aes_nonce or os.urandom(12)
    shared = eph.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(peer_pub_hex.removeprefix("0x"))))
    key = derive(shared)
    ct = AESGCM(key).encrypt(aes_nonce, plaintext.encode(), aad_bytes)
    blob = (_raw(eph.public_key()) + aes_nonce + ct).hex()
    return blob, {"ephemeral_private": _priv_raw(eph).hex(), "ephemeral_public": _raw(eph.public_key()).hex(),
                  "shared_secret": shared.hex(), "aes_key": key.hex(), "aes_nonce": aes_nonce.hex(),
                  "aad": aad_bytes.decode(), "plaintext": plaintext, "ciphertext_blob": blob}


def decrypt_field(my_priv: X25519PrivateKey, blob_hex: str, aad_bytes: bytes) -> tuple[str, dict]:
    blob = bytes.fromhex(blob_hex)
    eph_pub, aes_nonce, ct = blob[:32], blob[32:44], blob[44:]
    shared = my_priv.exchange(X25519PublicKey.from_public_bytes(eph_pub))
    key = derive(shared)
    pt = AESGCM(key).decrypt(aes_nonce, ct, aad_bytes).decode()
    return pt, {"server_ephemeral_public": eph_pub.hex(), "shared_secret": shared.hex(), "aes_key": key.hex(),
                "aes_nonce": aes_nonce.hex(), "aad": aad_bytes.decode(), "ciphertext_blob": blob_hex, "plaintext": pt}


def new_client_key() -> tuple[X25519PrivateKey, str, str]:
    k = X25519PrivateKey.generate()
    return k, _priv_raw(k).hex(), _raw(k.public_key()).hex()


RESPONSE_FIELDS = ("content", "reasoning", "reasoning_content")
