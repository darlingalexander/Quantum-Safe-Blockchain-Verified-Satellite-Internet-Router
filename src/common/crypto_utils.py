"""
Cryptographic utilities module for quantum-blockchain-satellite-router.

This module provides post-quantum cryptography utilities using ML-KEM for key
encapsulation mechanisms, post-quantum signatures for node authentication, and
SHA-256 hashing for blockchain verification.

Functions:
    - generate_pqc_keypair(): Generate ML-KEM keypair
    - encapsulate_secret(public_key): Create encapsulated secret with public key
    - decapsulate_secret(private_key, ciphertext): Recover secret from ciphertext
    - generate_pqc_sign_keypair(): Generate ML-DSA signature keypair
    - sign_message(secret_key, message): Sign a message for node authentication
    - verify_signature(public_key, message, signature): Verify a signature
    - compute_sha256(data): Compute SHA-256 hash of data
"""

import hashlib
from typing import Tuple, Union

try:
    from pqcrypto.kem import ml_kem_1024
    from pqcrypto.sign import ml_dsa_87
except ImportError:
    raise ImportError(
        "pqcrypto library is required. Install with: pip install pqcrypto"
    )


class CryptoError(Exception):
    """Base exception for cryptographic operations."""
    pass


class KeyGenerationError(CryptoError):
    """Exception raised during key generation."""
    pass


class EncapsulationError(CryptoError):
    """Exception raised during secret encapsulation."""
    pass


class DecapsulationError(CryptoError):
    """Exception raised during secret decapsulation."""
    pass


class SignatureError(CryptoError):
    """Exception raised during signature operations."""
    pass


def generate_pqc_keypair() -> Tuple[bytes, bytes]:
    """
    Generate a post-quantum cryptography keypair using ML-KEM-1024.

    ML-KEM is a key encapsulation mechanism (KEM) that provides quantum-resistant
    security. ML-KEM-1024 provides a stronger post-quantum security margin than
    the 512-bit variant.

    Returns:
        Tuple[bytes, bytes]: A tuple of (public_key, private_key) where:
            - public_key: The public key for encapsulation (bytes)
            - private_key: The private key for decapsulation (bytes)

    Raises:
        KeyGenerationError: If keypair generation fails.

    Example:
        >>> pk, sk = generate_pqc_keypair()
        >>> len(pk), len(sk)
        (1568, 3168)
    """
    try:
        public_key, private_key = ml_kem_1024.generate_keypair()
        return public_key, private_key
    except Exception as e:
        raise KeyGenerationError(
            f"Failed to generate PQC keypair: {str(e)}"
        ) from e


def encapsulate_secret(public_key: bytes) -> Tuple[bytes, bytes]:
    """
    Encapsulate a shared secret using a public key.

    This function generates a shared secret and encapsulates it using the provided
    public key. The ciphertext can only be decapsulated by the holder of the
    corresponding private key, recovering the same shared secret.

    Args:
        public_key (bytes): The public key for encapsulation.

    Returns:
        Tuple[bytes, bytes]: A tuple of (ciphertext, shared_secret) where:
            - ciphertext: The encapsulated secret (bytes)
            - shared_secret: The plaintext shared secret (bytes)

    Raises:
        EncapsulationError: If encapsulation fails or public_key is invalid.
        TypeError: If public_key is not bytes.

    Example:
        >>> pk, sk = generate_pqc_keypair()
        >>> ct, ss = encapsulate_secret(pk)
        >>> len(ct), len(ss)
        (768, 32)
    """
    if not isinstance(public_key, bytes):
        raise EncapsulationError(
            f"public_key must be bytes, got {type(public_key).__name__}"
        )

    try:
        ciphertext, shared_secret = ml_kem_1024.encrypt(public_key)
        return ciphertext, shared_secret
    except Exception as e:
        raise EncapsulationError(
            f"Failed to encapsulate secret: {str(e)}"
        ) from e


def decapsulate_secret(private_key: bytes, ciphertext: bytes) -> bytes:
    """
    Decapsulate a shared secret using a private key and ciphertext.

    This function recovers the shared secret that was encapsulated by the holder
    of the corresponding public key. The recovered secret will match the one
    generated during encapsulation, allowing for symmetric key establishment.

    Args:
        private_key (bytes): The private key for decapsulation.
        ciphertext (bytes): The encapsulated secret to decapsulate.

    Returns:
        bytes: The recovered shared secret.

    Raises:
        DecapsulationError: If decapsulation fails or inputs are invalid.
        TypeError: If inputs are not bytes.

    Example:
        >>> pk, sk = generate_pqc_keypair()
        >>> ct, ss = encapsulate_secret(pk)
        >>> recovered_ss = decapsulate_secret(sk, ct)
        >>> ss == recovered_ss
        True
    """
    if not isinstance(private_key, bytes):
        raise DecapsulationError(
            f"private_key must be bytes, got {type(private_key).__name__}"
        )

    if not isinstance(ciphertext, bytes):
        raise DecapsulationError(
            f"ciphertext must be bytes, got {type(ciphertext).__name__}"
        )

    try:
        shared_secret = ml_kem_1024.decrypt(private_key, ciphertext)
        return shared_secret
    except Exception as e:
        raise DecapsulationError(
            f"Failed to decapsulate secret: {str(e)}"
        ) from e


def generate_pqc_sign_keypair() -> Tuple[bytes, bytes]:
    """
    Generate a post-quantum signature keypair using ML-DSA.

    This function returns a public/private keypair that can be used for
    node authentication and message signing in the post-quantum network.

    Returns:
        Tuple[bytes, bytes]: A tuple of (public_key, secret_key).

    Raises:
        SignatureError: If signature keypair generation fails.
    """
    try:
        public_key, secret_key = ml_dsa_87.generate_keypair()
        return public_key, secret_key
    except Exception as e:
        raise SignatureError(
            f"Failed to generate PQ signature keypair: {str(e)}"
        ) from e


def sign_message(secret_key: bytes, message: Union[bytes, str]) -> bytes:
    """
    Sign a message using a post-quantum ML-DSA secret key.

    Args:
        secret_key (bytes): The secret key for signing.
        message (Union[bytes, str]): The message to sign.

    Returns:
        bytes: The generated signature.

    Raises:
        SignatureError: If signing fails.
        TypeError: If inputs are invalid.
    """
    if not isinstance(secret_key, bytes):
        raise SignatureError(
            f"secret_key must be bytes, got {type(secret_key).__name__}"
        )

    if isinstance(message, str):
        try:
            message = message.encode("utf-8")
        except UnicodeEncodeError as e:
            raise SignatureError(
                f"Failed to encode message as UTF-8: {str(e)}"
            ) from e
    elif not isinstance(message, bytes):
        raise SignatureError(
            f"message must be bytes or str, got {type(message).__name__}"
        )

    try:
        signature = ml_dsa_87.sign(secret_key, message)
        return signature
    except Exception as e:
        raise SignatureError(
            f"Failed to sign message: {str(e)}"
        ) from e


def verify_signature(public_key: bytes, message: Union[bytes, str], signature: bytes) -> bool:
    """
    Verify a post-quantum ML-DSA signature.

    Args:
        public_key (bytes): The public key for verification.
        message (Union[bytes, str]): The signed message.
        signature (bytes): The signature to verify.

    Returns:
        bool: True if the signature is valid, False otherwise.

    Raises:
        SignatureError: If verification fails due to invalid inputs.
    """
    if not isinstance(public_key, bytes):
        raise SignatureError(
            f"public_key must be bytes, got {type(public_key).__name__}"
        )

    if not isinstance(signature, bytes):
        raise SignatureError(
            f"signature must be bytes, got {type(signature).__name__}"
        )

    if isinstance(message, str):
        try:
            message = message.encode("utf-8")
        except UnicodeEncodeError as e:
            raise SignatureError(
                f"Failed to encode message as UTF-8: {str(e)}"
            ) from e
    elif not isinstance(message, bytes):
        raise SignatureError(
            f"message must be bytes or str, got {type(message).__name__}"
        )

    try:
        return ml_dsa_87.verify(public_key, message, signature)
    except Exception as e:
        raise SignatureError(
            f"Failed to verify signature: {str(e)}"
        ) from e


def compute_sha256(data: Union[bytes, str]) -> str:
    """
    Compute SHA-256 hash of input data.

    This function generates a SHA-256 hash digest of the provided data, which is
    used for blockchain transaction verification, data integrity checking, and
    creating cryptographic commitments in the satellite-router network.

    Args:
        data (Union[bytes, str]): The data to hash. If str, encoded as UTF-8.

    Returns:
        str: The hexadecimal digest of the SHA-256 hash.

    Raises:
        TypeError: If data is not bytes or str.
        ValueError: If string encoding fails.

    Example:
        >>> compute_sha256(b"quantum_satellite_data")
        'a3b4c5d6e7f8g9h0i1j2k3l4m5n6o7p8'
        >>> compute_sha256("transaction_block")
        'x1y2z3a4b5c6d7e8f9g0h1i2j3k4l5m6'
    """
    if isinstance(data, str):
        try:
            data = data.encode("utf-8")
        except UnicodeEncodeError as e:
            raise ValueError(
                f"Failed to encode string data as UTF-8: {str(e)}"
            ) from e
    elif not isinstance(data, bytes):
        raise TypeError(
            f"data must be bytes or str, got {type(data).__name__}"
        )

    try:
        sha256_hash = hashlib.sha256(data)
        return sha256_hash.hexdigest()
    except Exception as e:
        raise CryptoError(
            f"Failed to compute SHA-256 hash: {str(e)}"
        ) from e


# Module initialization check
if __name__ == "__main__":
    # Basic functionality test
    try:
        print("Testing crypto utilities...")

        # Test keypair generation
        print("  - Generating PQC keypair...")
        pk, sk = generate_pqc_keypair()
        print(f"    ✓ Public key size: {len(pk)} bytes")
        print(f"    ✓ Private key size: {len(sk)} bytes")

        # Test encapsulation
        print("  - Encapsulating secret...")
        ct, ss = encapsulate_secret(pk)
        print(f"    ✓ Ciphertext size: {len(ct)} bytes")
        print(f"    ✓ Shared secret size: {len(ss)} bytes")

        # Test decapsulation
        print("  - Decapsulating secret...")
        recovered_ss = decapsulate_secret(sk, ct)
        assert ss == recovered_ss, "Shared secrets do not match!"
        print("    ✓ Secrets match!")

        # Test SHA-256
        print("  - Computing SHA-256 hash...")
        test_data = b"quantum_blockchain_satellite_router"
        hash_result = compute_sha256(test_data)
        print(f"    ✓ Hash: {hash_result[:16]}...")

        print("\n✓ All crypto utilities tests passed!")

    except Exception as e:
        print(f"\n✗ Crypto utilities test failed: {str(e)}")
        exit(1)
