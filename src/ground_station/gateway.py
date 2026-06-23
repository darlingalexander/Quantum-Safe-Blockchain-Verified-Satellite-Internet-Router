"""
Ground Station Gateway microservice.

POST /payload
- Accepts JSON: {"data": <str>, "url": <destination_url>}
- Computes SHA-256 of `data` using src.common.crypto_utils.compute_sha256
- Creates a ledger entry mapping hash -> sequential tx id
- Generates legacy ECDSA signature via src.common.legacy_crypto.sign_ecdsa
- Encapsulates a session key for destination using Kyber-768 via crypto_utils
- Packages encrypted payload, ciphertext token, sha256 hash, ecdsa signature, and metadata
"""
import json
import threading
import os
from typing import Dict, Any

from flask import Flask, jsonify, request
import requests
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from src.common.crypto_utils import (
    compute_sha256,
    encapsulate_kem_768,
    generate_pqc_keypair_768,
)
from src.common.legacy_crypto import sign_ecdsa, get_public_key_hex


app = Flask(__name__)

# Simple in-memory ledger mapping transaction_hash -> tx_id
_ledger_lock = threading.Lock()
_ledger: Dict[str, int] = {}
_next_tx_id = 1


def _assign_tx_id(tx_hash: str) -> int:
    global _next_tx_id
    with _ledger_lock:
        if tx_hash in _ledger:
            return _ledger[tx_hash]
        tx_id = _next_tx_id
        _ledger[tx_hash] = tx_id
        _next_tx_id += 1
        return tx_id


def _symmetric_encrypt(shared_key: bytes, plaintext: bytes) -> Dict[str, str]:
    # Use AES-GCM for authenticated encryption
    key = shared_key[:32]
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return {
        "ciphertext": ciphertext.hex(),
        "nonce": nonce.hex(),
        "tag": tag.hex(),
    }


@app.route("/payload", methods=["POST"])
def payload() -> Any:
    print("Received /payload request")
    try:
        body = request.get_json(force=True)
    except Exception:
        print("Invalid JSON in request")
        return jsonify({"error": "Invalid JSON"}), 400

    data = body.get("data")
    dest_url = body.get("url")
    if not isinstance(data, str) or not isinstance(dest_url, str):
        print("Bad request: missing data or url")
        return jsonify({"error": "Request must include 'data' (str) and 'url' (str)"}), 400

    print("Computing SHA-256 of payload data")
    tx_hash = compute_sha256(data)
    print(f"Transaction hash: {tx_hash}")

    tx_id = _assign_tx_id(tx_hash)
    print(f"Assigned tx_id: {tx_id}")

    # Legacy ECDSA signature over the SHA-256 transaction hash
    print("Generating legacy ECDSA signature for transaction hash")
    signature_bytes = sign_ecdsa(tx_hash.encode("utf-8"))
    signature_hex = signature_bytes.hex()
    signing_pubkey_hex = get_public_key_hex()
    print(f"Signature: {signature_hex[:32]}...", f"pubkey: {signing_pubkey_hex}")

    # Obtain destination PQ public key (mock): try GET {dest_url}/pqc_pubkey
    dest_pubkey = None
    try:
        print(f"Attempting to fetch destination PQ public key from {dest_url}/pqc_pubkey")
        r = requests.get(dest_url.rstrip('/') + '/pqc_pubkey', timeout=2)
        if r.status_code == 200:
            j = r.json()
            pk_hex = j.get('public_key')
            if isinstance(pk_hex, str):
                dest_pubkey = bytes.fromhex(pk_hex)
                print("Obtained destination public key from remote")
    except Exception as e:
        print("Could not fetch destination public key; performing local mock keypair generation", str(e))

    if dest_pubkey is None:
        print("Generating ephemeral destination keypair (mock)")
        dest_pk, dest_sk = generate_pqc_keypair_768()
        dest_pubkey = dest_pk

    # Encapsulate a session key for the destination using Kyber-768
    print("Encapsulating session key for destination (Kyber-768)")
    ciphertext_token, shared_secret = encapsulate_kem_768(dest_pubkey)
    print(f"Ciphertext token size: {len(ciphertext_token)} bytes")

    # Symmetric encrypt the payload using the shared secret
    print("Encrypting payload with derived session key")
    enc = _symmetric_encrypt(shared_secret, data.encode("utf-8"))

    packet = {
        "encrypted_payload": enc['ciphertext'],
        "cipher_meta": {
            "nonce": enc['nonce'],
            "tag": enc['tag'],
        },
        "ciphertext_token": ciphertext_token.hex(),
        "transaction_hash": tx_hash,
        "transaction_id": tx_id,
        "legacy_ecdsa_signature": signature_hex,
        "legacy_signing_public_key": signing_pubkey_hex,
        "destination": dest_url,
    }

    # Register transaction with the Immutable Verification Ledger
    ledger_post_url = "http://localhost:5003/transaction/new"
    ledger_mine_url = "http://localhost:5003/mine"
    ledger_body = {
        "transaction_id": tx_id,
        "transaction_hash": tx_hash,
        "legacy_signature": signature_hex,
        "signing_public_key": signing_pubkey_hex,
    }
    try:
        print(f"Posting transaction to ledger: {ledger_post_url} -> tx_id={tx_id}")
        ledger_resp = requests.post(ledger_post_url, json=ledger_body, timeout=3)
        print(f"Ledger POST response: {ledger_resp.status_code}")
    except Exception as e:
        print(f"Failed to POST transaction to ledger: {e}")

    # Trigger mining to confirm the transaction in this simulation
    try:
        print(f"Triggering ledger mining: {ledger_mine_url}")
        mine_resp = requests.get(ledger_mine_url, timeout=5)
        print(f"Ledger mine response: {mine_resp.status_code}")
    except Exception as e:
        print(f"Failed to trigger ledger mining: {e}")

    # For demonstration, attempt to POST the packet to the destination relay
    try:
        print(f"Relaying packet to {dest_url}")
        resp = requests.post(dest_url, json=packet, timeout=3)
        print(f"Relay response: {resp.status_code}")
    except Exception as e:
        print(f"Relay to destination failed: {e}")

    return jsonify({"status": "ok", "transaction_id": tx_id, "transaction_hash": tx_hash}), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)
