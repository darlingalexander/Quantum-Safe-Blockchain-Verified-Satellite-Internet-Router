"""
Pytest test suite for crypto_utils module.

Tests the post-quantum cryptographic utilities including ML-KEM-1024 key
generation, encapsulation/decapsulation of secrets, ML-DSA signature signing and
verification, and SHA-256 hashing.
"""

import pytest
from src.common.crypto_utils import (
    generate_pqc_keypair,
    encapsulate_secret,
    decapsulate_secret,
    generate_pqc_sign_keypair,
    sign_message,
    verify_signature,
    compute_sha256,
    CryptoError,
    KeyGenerationError,
    EncapsulationError,
    DecapsulationError,
    SignatureError,
)


class TestGeneratePQCKeypair:
    """Test suite for generate_pqc_keypair function."""

    def test_generate_keypair_returns_tuple(self):
        """Test that generate_pqc_keypair returns a tuple."""
        result = generate_pqc_keypair()
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_generate_keypair_returns_bytes(self):
        """Test that generate_pqc_keypair returns bytes objects."""
        pk, sk = generate_pqc_keypair()
        assert isinstance(pk, bytes)
        assert isinstance(sk, bytes)

    def test_generate_keypair_key_sizes(self):
        """Test that generated keys have expected sizes for ML-KEM-1024."""
        pk, sk = generate_pqc_keypair()
        # ML-KEM-1024: public key = 1568 bytes, secret key = 3168 bytes
        assert len(pk) == 1568
        assert len(sk) == 3168

    def test_generate_keypair_uniqueness(self):
        """Test that multiple keypair generations produce different keys."""
        pk1, sk1 = generate_pqc_keypair()
        pk2, sk2 = generate_pqc_keypair()
        assert pk1 != pk2
        assert sk1 != sk2

    def test_generate_keypair_consistent_format(self):
        """Test that generated keys maintain consistent format across calls."""
        for _ in range(5):
            pk, sk = generate_pqc_keypair()
            assert len(pk) == 1568
            assert len(sk) == 3168
            assert all(isinstance(b, int) and 0 <= b < 256 for b in pk)
            assert all(isinstance(b, int) and 0 <= b < 256 for b in sk)


class TestEncapsulationDecapsulation:
    """Test suite for encapsulate_secret and decapsulate_secret functions."""

    @pytest.fixture
    def keypair(self):
        """Generate a keypair for testing."""
        return generate_pqc_keypair()

    def test_encapsulate_returns_tuple(self, keypair):
        """Test that encapsulate_secret returns a tuple."""
        pk, _ = keypair
        result = encapsulate_secret(pk)
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_encapsulate_returns_bytes(self, keypair):
        """Test that encapsulate_secret returns bytes objects."""
        pk, _ = keypair
        ct, ss = encapsulate_secret(pk)
        assert isinstance(ct, bytes)
        assert isinstance(ss, bytes)

    def test_encapsulate_sizes(self, keypair):
        """Test that encapsulated outputs have expected sizes for ML-KEM-1024."""
        pk, _ = keypair
        ct, ss = encapsulate_secret(pk)
        # ML-KEM-1024: ciphertext = 1568 bytes, shared secret = 32 bytes
        assert len(ct) == 1568
        assert len(ss) == 32

    def test_encapsulate_invalid_key_type(self):
        """Test that encapsulate_secret raises error for non-bytes key."""
        with pytest.raises(EncapsulationError):
            encapsulate_secret("not bytes")
        with pytest.raises(EncapsulationError):
            encapsulate_secret(123)
        with pytest.raises(EncapsulationError):
            encapsulate_secret(None)

    def test_decapsulate_returns_bytes(self, keypair):
        """Test that decapsulate_secret returns bytes."""
        pk, sk = keypair
        ct, _ = encapsulate_secret(pk)
        result = decapsulate_secret(sk, ct)
        assert isinstance(result, bytes)

    def test_encapsulate_decapsulate_match(self, keypair):
        """Test that decapsulated secret matches the encapsulated one."""
        pk, sk = keypair
        ct, original_ss = encapsulate_secret(pk)
        recovered_ss = decapsulate_secret(sk, ct)
        assert original_ss == recovered_ss
        assert len(recovered_ss) == 32

    def test_encapsulate_decapsulate_multiple_rounds(self):
        """Test multiple rounds of encapsulation/decapsulation."""
        for _ in range(5):
            pk, sk = generate_pqc_keypair()
            ct, ss = encapsulate_secret(pk)
            recovered_ss = decapsulate_secret(sk, ct)
            assert ss == recovered_ss

    def test_different_encapsulations_produce_different_secrets(self, keypair):
        """Test that different encapsulations produce different ciphertexts and secrets."""
        pk, _ = keypair
        ct1, ss1 = encapsulate_secret(pk)
        ct2, ss2 = encapsulate_secret(pk)
        assert ct1 != ct2
        assert ss1 != ss2

    def test_decapsulate_invalid_key_type(self, keypair):
        """Test that decapsulate_secret raises error for non-bytes inputs."""
        pk, sk = keypair
        ct, _ = encapsulate_secret(pk)
        
        with pytest.raises(DecapsulationError):
            decapsulate_secret("not bytes", ct)
        with pytest.raises(DecapsulationError):
            decapsulate_secret(sk, "not bytes")

    def test_decapsulate_invalid_key_size(self, keypair):
        """Test that decapsulate_secret raises error for wrong key/ciphertext size."""
        pk, sk = keypair
        ct, _ = encapsulate_secret(pk)
        
        # Wrong size secret key
        with pytest.raises(DecapsulationError):
            decapsulate_secret(sk[:100], ct)
        
        # Wrong size ciphertext
        with pytest.raises(DecapsulationError):
            decapsulate_secret(sk, ct[:100])


class TestSignatureWorkflow:
    """Test suite for ML-DSA signature generation and verification."""

    def test_generate_signature_keypair(self):
        """Test that ML-DSA signing keypair generation returns bytes."""
        pk, sk = generate_pqc_sign_keypair()
        assert isinstance(pk, bytes)
        assert isinstance(sk, bytes)
        assert len(pk) > 0
        assert len(sk) > 0

    def test_sign_and_verify_message(self):
        """Test that ML-DSA signatures verify correctly."""
        pk, sk = generate_pqc_sign_keypair()
        message = "node_authentication_message"
        signature = sign_message(sk, message)

        assert isinstance(signature, bytes)
        assert len(signature) > 0
        assert verify_signature(pk, message, signature) is True

    def test_verify_with_modified_message_fails(self):
        """Test that verification fails for a modified message."""
        pk, sk = generate_pqc_sign_keypair()
        message = "original_message"
        signature = sign_message(sk, message)

        assert verify_signature(pk, "tampered_message", signature) is False

    def test_sign_invalid_types_raise(self):
        """Test that signature methods validate input types."""
        pk, sk = generate_pqc_sign_keypair()
        with pytest.raises(SignatureError):
            sign_message("not bytes", "message")
        with pytest.raises(SignatureError):
            sign_message(sk, 123)
        with pytest.raises(SignatureError):
            verify_signature("not bytes", "message", b"signature")
        with pytest.raises(SignatureError):
            verify_signature(pk, 123, b"signature")
        with pytest.raises(SignatureError):
            verify_signature(pk, "message", "not bytes")


class TestComputeSHA256:
    """Test suite for compute_sha256 function."""

    def test_sha256_returns_string(self):
        """Test that compute_sha256 returns a string."""
        result = compute_sha256(b"test")
        assert isinstance(result, str)

    def test_sha256_hex_format(self):
        """Test that compute_sha256 returns a valid hexadecimal string."""
        result = compute_sha256(b"test")
        assert len(result) == 64  # SHA-256 produces 64 hex characters
        assert all(c in "0123456789abcdef" for c in result)

    def test_sha256_known_value_bytes(self):
        """Test compute_sha256 against known SHA-256 hash."""
        # Known hash for empty string
        result = compute_sha256(b"")
        expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert result == expected

    def test_sha256_string_input(self):
        """Test compute_sha256 with string input."""
        result_bytes = compute_sha256(b"quantum")
        result_str = compute_sha256("quantum")
        assert result_bytes == result_str

    def test_sha256_string_encoding_utf8(self):
        """Test that string inputs are properly encoded as UTF-8."""
        # Unicode character
        result = compute_sha256("café")
        assert isinstance(result, str)
        assert len(result) == 64

    def test_sha256_invalid_input_type(self):
        """Test that compute_sha256 raises error for invalid input types."""
        with pytest.raises(TypeError):
            compute_sha256(123)
        with pytest.raises(TypeError):
            compute_sha256(None)
        with pytest.raises(TypeError):
            compute_sha256([b"test"])

    def test_sha256_deterministic(self):
        """Test that compute_sha256 is deterministic."""
        data = "blockchain_transaction_hash"
        hash1 = compute_sha256(data)
        hash2 = compute_sha256(data)
        hash3 = compute_sha256(data)
        assert hash1 == hash2 == hash3

    def test_sha256_different_inputs(self):
        """Test that different inputs produce different hashes."""
        hash1 = compute_sha256("satellite_node_1")
        hash2 = compute_sha256("satellite_node_2")
        hash3 = compute_sha256("satellite_node_1 ")  # With trailing space
        assert hash1 != hash2
        assert hash1 != hash3

    def test_sha256_case_sensitive(self):
        """Test that SHA-256 is case-sensitive."""
        hash_lower = compute_sha256("quantum")
        hash_upper = compute_sha256("QUANTUM")
        assert hash_lower != hash_upper

    def test_sha256_long_input(self):
        """Test compute_sha256 with long input."""
        long_data = "x" * 10000
        result = compute_sha256(long_data)
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_sha256_binary_data(self):
        """Test compute_sha256 with binary data."""
        binary_data = bytes(range(256))
        result = compute_sha256(binary_data)
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_sha256_blockchain_use_case(self):
        """Test SHA-256 for blockchain transaction hashing."""
        # Simulate a transaction block
        transaction = "sender:receiver:amount:timestamp"
        tx_hash = compute_sha256(transaction)
        
        assert isinstance(tx_hash, str)
        assert len(tx_hash) == 64
        
        # Verify determinism for blockchain
        assert compute_sha256(transaction) == tx_hash


class TestExceptionHierarchy:
    """Test exception classes and their inheritance."""

    def test_crypto_error_base_exception(self):
        """Test that CryptoError is an Exception."""
        assert issubclass(CryptoError, Exception)

    def test_custom_exceptions_inherit_from_crypto_error(self):
        """Test that custom exceptions inherit from CryptoError."""
        assert issubclass(KeyGenerationError, CryptoError)
        assert issubclass(EncapsulationError, CryptoError)
        assert issubclass(DecapsulationError, CryptoError)
        assert issubclass(SignatureError, CryptoError)

    def test_exception_can_be_caught_as_base(self):
        """Test that specific exceptions can be caught as CryptoError."""
        pk, _ = generate_pqc_keypair()
        
        try:
            encapsulate_secret("invalid")
        except CryptoError as e:
            assert isinstance(e, EncapsulationError)


class TestIntegration:
    """Integration tests for complete cryptographic workflows."""

    def test_full_key_exchange_workflow(self):
        """Test a complete key exchange workflow."""
        # Alice generates keypair
        alice_pk, alice_sk = generate_pqc_keypair()
        
        # Bob sends a secret to Alice
        ciphertext, bob_secret = encapsulate_secret(alice_pk)
        
        # Alice recovers the secret
        alice_secret = decapsulate_secret(alice_sk, ciphertext)
        
        # Verify they have the same secret
        assert alice_secret == bob_secret

    def test_multiple_independent_key_exchanges(self):
        """Test multiple independent key exchanges."""
        exchanges = []
        for i in range(3):
            pk, sk = generate_pqc_keypair()
            ct, ss = encapsulate_secret(pk)
            recovered_ss = decapsulate_secret(sk, ct)
            exchanges.append({
                'pk': pk,
                'sk': sk,
                'ct': ct,
                'original_ss': ss,
                'recovered_ss': recovered_ss
            })
        
        # Verify all exchanges succeeded independently
        for exchange in exchanges:
            assert exchange['original_ss'] == exchange['recovered_ss']

    def test_blockchain_verification_workflow(self):
        """Test blockchain transaction verification workflow."""
        # Create transactions
        transactions = [
            "tx1:sender_A:receiver_B:100",
            "tx2:sender_C:receiver_D:200",
            "tx3:sender_E:receiver_F:300",
        ]
        
        # Hash each transaction
        tx_hashes = [compute_sha256(tx) for tx in transactions]
        
        # Verify uniqueness
        assert len(set(tx_hashes)) == len(tx_hashes)
        
        # Verify determinism
        for tx, expected_hash in zip(transactions, tx_hashes):
            assert compute_sha256(tx) == expected_hash
