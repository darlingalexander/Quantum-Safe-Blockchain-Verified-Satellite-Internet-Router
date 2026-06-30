"""
Legacy ECDSA helpers for backwards compatibility.

Provides simple ECDSA signing utilities used by legacy network components.
"""
import os
from typing import Tuple

from ecdsa import SECP256k1, SigningKey


class LegacyCryptoError(Exception):
    pass


def _load_or_generate_key() -> SigningKey:
    env_hex = os.getenv("LEGACY_ECDSA_PRIVKEY_HEX")
    if env_hex:
        try:
            sk_bytes = bytes.fromhex(env_hex)
            return SigningKey.from_string(sk_bytes, curve=SECP256k1)
        except Exception as e:
            raise LegacyCryptoError("Invalid LEGACY_ECDSA_PRIVKEY_HEX") from e

    # Generate ephemeral key
    return SigningKey.generate(curve=SECP256k1)


_SIGNING_KEY = _load_or_generate_key()


def get_public_key_hex() -> str:
    """Return the verifying (public) key in compressed hex format."""
    return _SIGNING_KEY.get_verifying_key().to_string("compressed").hex()


def sign_ecdsa(message: bytes) -> bytes:
    """Sign the given message bytes with the legacy ECDSA key.

    Args:
        message (bytes): Message to sign.

    Returns:
        bytes: Signature bytes.

    Raises:
        LegacyCryptoError: If input is invalid or signing fails.
    """
    if not isinstance(message, (bytes, bytearray)):
        raise LegacyCryptoError("message must be bytes")

    try:
        return _SIGNING_KEY.sign(message)
    except Exception as e:
        raise LegacyCryptoError("Failed to sign message") from e
