#!/usr/bin/env python3
"""
Tests for the Home Router `/receive` endpoint.

- Test Case 1: Valid payload -> 200 OK
- Test Case 2: Altered data / hash mismatch -> 400 Bad Request
- Test Case 3: Tampered KEM ciphertext triggers DecapsulationError -> 401 Unauthorized
"""

import json
from unittest.mock import patch

import pytest
from Crypto.Cipher import AES

from src.router.home_router import app
from src.common.crypto_utils import compute_sha256, DecapsulationError


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def _encrypt_with_shared_secret(shared_secret: bytes, plaintext: str):
    key = shared_secret[:32]
    # deterministic nonce for tests
    nonce = b"\x00" * 12
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    return ciphertext.hex(), nonce.hex(), tag.hex()


def _build_packet(ciphertext_token_hex: str, ciphertext_hex: str, nonce_hex: str, tag_hex: str, tx_hash: str, tx_id: int):
    return {
        "ciphertext_token": ciphertext_token_hex,
        "encrypted_payload": ciphertext_hex,
        "cipher_meta": {"nonce": nonce_hex, "tag": tag_hex},
        "transaction_hash": tx_hash,
        "transaction_id": tx_id,
    }


class TestHomeRouterReceive:
    def test_valid_payload_returns_200(self, client):
        shared_secret = b"\x01" * 32
        data_str = "valid transaction payload"
        ciphertext_hex, nonce_hex, tag_hex = _encrypt_with_shared_secret(shared_secret, data_str)
        tx_hash = compute_sha256(data_str)
        # KEM ciphertext token is arbitrary here because decapsulation is mocked
        ct_token_hex = (b"kemcipher" ).hex()

        packet = _build_packet(ct_token_hex, ciphertext_hex, nonce_hex, tag_hex, tx_hash, 100)

        with patch("src.router.home_router.decapsulate_secret", return_value=shared_secret) as mock_decaps:
            resp = client.post("/receive", data=json.dumps(packet), content_type="application/json")
            assert resp.status_code == 200
            assert resp.json["status"] == "accepted"
            assert resp.json["transaction_id"] == 100
            mock_decaps.assert_called_once()

    def test_altered_data_detected_and_rejected_400(self, client):
        shared_secret = b"\x02" * 32
        original_data = "original payload"
        ciphertext_hex, nonce_hex, tag_hex = _encrypt_with_shared_secret(shared_secret, original_data)
        # Tampered data simulation: change the expected hash to that of a different string
        tampered_hash = compute_sha256("modified payload")
        ct_token_hex = (b"kemcipher2").hex()

        packet = _build_packet(ct_token_hex, ciphertext_hex, nonce_hex, tag_hex, tampered_hash, 101)

        with patch("src.router.home_router.decapsulate_secret", return_value=shared_secret):
            resp = client.post("/receive", data=json.dumps(packet), content_type="application/json")
            assert resp.status_code == 400
            assert "hash" in resp.json["message"] or "tamper" in resp.json["message"].lower()

    def test_tampered_ciphertext_token_triggers_decapsulation_error_401(self, client):
        # Build a packet with arbitrary ciphertext but patch decapsulation to raise
        shared_secret = b"\x03" * 32
        data_str = "payload for decap error"
        ciphertext_hex, nonce_hex, tag_hex = _encrypt_with_shared_secret(shared_secret, data_str)
        tx_hash = compute_sha256(data_str)
        ct_token_hex = (b"invalid_kem_ct").hex()

        packet = _build_packet(ct_token_hex, ciphertext_hex, nonce_hex, tag_hex, tx_hash, 102)

        with patch("src.router.home_router.decapsulate_secret", side_effect=DecapsulationError("decap failed")) as mock_decap:
            resp = client.post("/receive", data=json.dumps(packet), content_type="application/json")
            assert resp.status_code == 401
            assert resp.json["status"] == "unauthorized"
            mock_decap.assert_called_once()
