#!/usr/bin/env python3
"""
Simulated Home Router Node (consumer-facing).

Runs a Flask app on port 5002 that:
- Persists/loads a Post-Quantum KEM keypair (public/private)
- Exposes POST /receive to accept unified JSON packets from the satellite
- Uses PQC decapsulation to recover the symmetric session key
- Decrypts the AES-GCM payload, recomputes SHA-256, and verifies integrity
"""

import os
import logging
from typing import Tuple

from flask import Flask, request, jsonify
from Crypto.Cipher import AES
import requests

from src.common.crypto_utils import (
    generate_pqc_keypair,
    decapsulate_secret,
    compute_sha256,
    DecapsulationError,
)


LOG = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

APP_DIR = os.path.dirname(__file__)
PRIV_KEY_PATH = os.path.join(APP_DIR, "pqc_private_key.bin")
PUB_KEY_PATH = os.path.join(APP_DIR, "pqc_public_key.hex")


def _load_or_generate_keypair() -> Tuple[bytes, bytes]:
    """Load persistent PQC keypair from disk or generate and persist one.

    Returns (public_key, private_key)
    """
    if os.path.exists(PRIV_KEY_PATH) and os.path.exists(PUB_KEY_PATH):
        LOG.info("Loading existing PQC keypair from disk")
        with open(PRIV_KEY_PATH, "rb") as f:
            sk = f.read()
        with open(PUB_KEY_PATH, "r", encoding="utf-8") as f:
            pk_hex = f.read().strip()
        pk = bytes.fromhex(pk_hex)
        return pk, sk

    LOG.info("No existing PQC keypair found — generating new one")
    pk, sk = generate_pqc_keypair()
    # Persist private key (binary) and public key (hex)
    with open(PRIV_KEY_PATH, "wb") as f:
        f.write(sk)
    with open(PUB_KEY_PATH, "w", encoding="utf-8") as f:
        f.write(pk.hex())
    LOG.info("Persisted PQC keypair to %s and %s", PRIV_KEY_PATH, PUB_KEY_PATH)
    return pk, sk


# Initialize keys
PUBLIC_KEY, PRIVATE_KEY = _load_or_generate_keypair()


app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False


@app.route("/pqc_pubkey", methods=["GET"])
def get_pqc_public_key():
    """Return the public key (hex) so ground stations can fetch it."""
    return jsonify({"public_key": PUBLIC_KEY.hex()}), 200


@app.route("/receive", methods=["POST"])
def receive_packet():
    """Accept unified JSON packet, decapsulate, decrypt, and verify hash.

    Expected JSON fields (from gateway):
      - ciphertext_token: hex string of KEM ciphertext
      - encrypted_payload: hex string of AES-GCM ciphertext
      - cipher_meta: {nonce: hex, tag: hex}
      - transaction_hash: str (sha256 hex)
      - transaction_id: int
    """
    LOG.info("/receive called from %s", request.remote_addr)

    if not request.is_json:
        LOG.warning("Rejecting non-JSON request")
        return jsonify({"status": "error", "message": "Content-Type must be application/json"}), 400

    packet = request.get_json()

    tx_id = packet.get("transaction_id", "UNKNOWN")
    tx_hash = packet.get("transaction_hash")

    LOG.info("Received packet tx_id=%s tx_hash=%.8s", tx_id, tx_hash)

    # Extract KEM ciphertext
    ct_hex = packet.get("ciphertext_token")
    if not isinstance(ct_hex, str):
        LOG.error("Missing or invalid ciphertext_token for tx_id=%s", tx_id)
        return jsonify({"status": "error", "message": "Missing ciphertext_token"}), 400

    try:
        ct = bytes.fromhex(ct_hex)
    except Exception as e:
        LOG.exception("Invalid ciphertext_token hex: %s", e)
        return jsonify({"status": "error", "message": "Invalid ciphertext_token hex"}), 400

    # Decapsulate using our persistent private key
    try:
        shared_secret = decapsulate_secret(PRIVATE_KEY, ct)
        LOG.info("Decapsulation success for tx_id=%s (recovered symmetric key)", tx_id)
    except DecapsulationError as e:
        LOG.error("Decapsulation failed for tx_id=%s: %s", tx_id, str(e))
        return jsonify({"status": "unauthorized", "message": "Decapsulation failed"}), 401
    except Exception as e:
        LOG.exception("Unexpected error during decapsulation for tx_id=%s: %s", tx_id, e)
        return jsonify({"status": "unauthorized", "message": "Decapsulation failed"}), 401

    # Decrypt AES-GCM payload
    enc_hex = packet.get("encrypted_payload")
    cipher_meta = packet.get("cipher_meta", {})
    nonce_hex = cipher_meta.get("nonce")
    tag_hex = cipher_meta.get("tag")

    if not all(isinstance(v, str) for v in (enc_hex, nonce_hex, tag_hex)):
        LOG.error("Missing encryption metadata for tx_id=%s", tx_id)
        return jsonify({"status": "error", "message": "Missing encryption metadata"}), 400

    try:
        ciphertext = bytes.fromhex(enc_hex)
        nonce = bytes.fromhex(nonce_hex)
        tag = bytes.fromhex(tag_hex)
    except Exception as e:
        LOG.exception("Failed to parse encryption hex fields for tx_id=%s: %s", tx_id, e)
        return jsonify({"status": "error", "message": "Invalid encryption hex fields"}), 400

    try:
        key = shared_secret[:32]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        # plaintext is bytes; convert to str for hashing
        try:
            data_str = plaintext.decode("utf-8")
        except Exception:
            # If plaintext is binary, treat as tampered
            LOG.error("Failed to decode plaintext as UTF-8 for tx_id=%s", tx_id)
            return jsonify({"status": "bad_request", "message": "Payload not valid UTF-8"}), 400
        LOG.info("Decryption success for tx_id=%s", tx_id)
    except (ValueError, KeyError) as e:
        LOG.error("Decryption/authentication failed for tx_id=%s: %s", tx_id, e)
        return jsonify({"status": "bad_request", "message": "Decryption failed or payload tampered"}), 400
    except Exception as e:
        LOG.exception("Unexpected decryption error for tx_id=%s: %s", tx_id, e)
        return jsonify({"status": "error", "message": "Decryption error"}), 400

    # Recompute SHA-256 and verify integrity
    try:
        recomputed = compute_sha256(data_str)
    except Exception as e:
        LOG.exception("Failed computing SHA-256 for tx_id=%s: %s", tx_id, e)
        return jsonify({"status": "error", "message": "Hash computation failed"}), 500

    if recomputed != tx_hash:
        LOG.critical(
            "Tampering alert: tx_id=%s recomputed_hash=%.8s expected_hash=%.8s",
            tx_id, recomputed, tx_hash,
        )
        return jsonify({"status": "bad_request", "message": "Payload hash mismatch - tampering suspected"}), 400
    # Verify the data hash against the immutable ledger before accepting
    ledger_url = f"http://localhost:5003/transaction/{tx_hash}"
    try:
        ledger_resp = requests.get(ledger_url, timeout=3)
        LOG.info("Ledger lookup for tx_hash=%.8s returned status=%s", tx_hash, ledger_resp.status_code)
        if ledger_resp.status_code != 200:
            LOG.error("Hash discrepancy on ledger for tx_id=%s tx_hash=%.8s - dropping packet", tx_id, tx_hash)
            return 'Hash discrepancy on ledger - Dropping packet', 400
    except Exception as e:
        LOG.exception("Failed to query ledger for tx_id=%s: %s", tx_id, e)
        return jsonify({"status": "error", "message": "Ledger lookup failed"}), 500

    LOG.info("Packet accepted: tx_id=%s hash verified", tx_id)
    return jsonify({"status": "accepted", "transaction_id": tx_id, "transaction_hash": tx_hash}), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy"}), 200


if __name__ == "__main__":
    LOG.info("Home Router Node starting on port 5002")
    LOG.info("Public key (hex): %s...", PUBLIC_KEY.hex()[:32])
    app.run(host="0.0.0.0", port=5002, debug=False)
