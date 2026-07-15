import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict

import requests
from ecdsa import SECP256k1, SigningKey
from flask import Flask, jsonify, request
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


if __package__ in (None, ""):
    # Support direct execution: python src/ground_station/app.py
    repo_root = Path(__file__).resolve().parents[2]
    repo_root_str = str(repo_root)
    if repo_root_str not in sys.path:
        sys.path.insert(0, repo_root_str)

from src.common.crypto_utils import compute_sha256_hex_digest, encapsulate_secret


app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
LOG = logging.getLogger(__name__)

SATELLITE_RELAY_URL = os.getenv(
    "SATELLITE_RELAY_URL", "http://127.0.0.1:5001/relay"
)
ECDSA_PRIVATE_KEY_HEX = os.getenv("GROUND_STATION_ECDSA_PRIVKEY_HEX")


def _payload_size_bytes(payload: Any) -> int:
    try:
        return len(json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8"))
    except Exception:
        return -1


def _log_packet_event(
    *,
    incoming_endpoint: str,
    destination_endpoint: str,
    payload_size_bytes: int,
    http_status_code: Any,
    forwarding_succeeded: bool,
    forwarding_failed: bool,
    relay_latency_ms: Any,
    packet_dropped: bool,
) -> None:
    LOG.info(
        "incoming_endpoint=%s destination_endpoint=%s payload_size_bytes=%s http_status_code=%s "
        "forwarding_succeeded=%s forwarding_failed=%s relay_latency_ms=%s packet_dropped=%s",
        incoming_endpoint,
        destination_endpoint,
        payload_size_bytes,
        http_status_code,
        forwarding_succeeded,
        forwarding_failed,
        relay_latency_ms,
        packet_dropped,
    )


def load_signing_key() -> SigningKey:
    """Load or generate a legacy ECDSA signing key for backwards compatibility."""
    if ECDSA_PRIVATE_KEY_HEX:
        try:
            private_bytes = bytes.fromhex(ECDSA_PRIVATE_KEY_HEX)
            return SigningKey.from_string(private_bytes, curve=SECP256k1)
        except Exception as exc:
            raise ValueError(
                "Invalid ECDSA private key hex in GROUND_STATION_ECDSA_PRIVKEY_HEX"
            ) from exc

    return SigningKey.generate(curve=SECP256k1)


SIGNING_KEY = load_signing_key()
PUBLIC_KEY_HEX = SIGNING_KEY.get_verifying_key().to_string("compressed").hex()


def generate_ecdsa_signature(message: bytes) -> str:
    """Generate a legacy ECDSA signature for the given message bytes."""
    signature_bytes = SIGNING_KEY.sign(message)
    return signature_bytes.hex()


def build_transaction_hash(payload: Dict[str, Any]) -> str:
    """Compute a deterministic SHA-256 hash for the transaction payload."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return compute_sha256_hex_digest(canonical)


def _symmetric_encrypt(shared_key: bytes, plaintext: bytes) -> Dict[str, str]:
    """Encrypt plaintext with AES-GCM using shared key material."""
    key = shared_key[:32]
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return {
        "ciphertext": ciphertext.hex(),
        "nonce": nonce.hex(),
        "tag": tag.hex(),
    }


@app.route("/broadcast", methods=["POST"])
def broadcast() -> Any:
    """Receive a transaction payload, sign and hash it, then relay to satellite."""
    print("[Ground Station] Packet received.")
    print("[GROUND] /broadcast called")
    print(f"[GROUND] Incoming headers: {dict(request.headers)}")

    try:
        incoming = request.get_json(force=True)
    except Exception as exc:
        print(f"[GROUND] 400 Invalid JSON payload: {exc}")
        return jsonify({"error": "Invalid JSON payload", "details": str(exc)}), 400

    print(f"[GROUND] Incoming JSON: {incoming}")
    incoming_payload_size = _payload_size_bytes(incoming)
    _log_packet_event(
        incoming_endpoint="/broadcast",
        destination_endpoint="N/A",
        payload_size_bytes=incoming_payload_size,
        http_status_code="N/A",
        forwarding_succeeded=False,
        forwarding_failed=False,
        relay_latency_ms="N/A",
        packet_dropped=False,
    )

    if not isinstance(incoming, dict):
        print("[GROUND] 400 Payload is not a JSON object")
        return jsonify({"error": "Payload must be a JSON object"}), 400

    # Normalize supported shapes:
    # - { "payload": { ... } }
    # - { "data": "...", "url": "..." }
    # - or the transaction dict directly
    if "payload" in incoming and isinstance(incoming["payload"], dict):
        payload = incoming["payload"]
    else:
        payload = incoming

    data_value = payload.get("data")
    destination = payload.get("url")
    intercept_enabled = payload.get("intercept", False)
    if not isinstance(data_value, str) or not isinstance(destination, str):
        print(f"[GROUND] 400 Missing required payload fields. payload={payload}")
        return jsonify({
            "error": "Payload must include 'data' (str) and 'url' (str)",
            "received_payload": payload,
        }), 400

    print("[Ground Station] Packet verified")

    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    # Router verifies hash over decrypted plaintext data only.
    transaction_hash = compute_sha256_hex_digest(data_value)
    # Ledger verifies legacy signatures over the transaction hash bytes.
    signature = generate_ecdsa_signature(transaction_hash.encode("utf-8"))

    # Obtain the router public key from the destination service so we can
    # construct the packet shape expected by the relay/home-router chain.
    pubkey_url = destination.rstrip("/")
    if pubkey_url.endswith("/receive"):
        pubkey_url = pubkey_url[: -len("/receive")]
    pubkey_url = pubkey_url.rstrip("/") + "/pqc_pubkey"

    try:
        pk_resp = requests.get(pubkey_url, timeout=3)
        if pk_resp.status_code != 200:
            print(f"[GROUND] 400 Destination key fetch failed: status={pk_resp.status_code}")
            return jsonify({
                "error": "Failed to fetch destination public key",
                "destination": destination,
                "pubkey_url": pubkey_url,
                "status_code": pk_resp.status_code,
            }), 400
        pk_json = pk_resp.json()
        pk_hex = pk_json.get("public_key")
        if not isinstance(pk_hex, str):
            print(f"[GROUND] 400 Invalid destination public key payload: {pk_json}")
            return jsonify({
                "error": "Destination public key response missing 'public_key'",
                "destination": destination,
                "pubkey_url": pubkey_url,
            }), 400
        destination_public_key = bytes.fromhex(pk_hex)
    except Exception as exc:
        print(f"[GROUND] 400 Could not fetch/parse destination public key: {exc}")
        return jsonify({
            "error": "Could not fetch destination public key",
            "destination": destination,
            "pubkey_url": pubkey_url,
            "details": str(exc),
        }), 400

    try:
        ciphertext_token, shared_secret = encapsulate_secret(destination_public_key)
        encrypted = _symmetric_encrypt(shared_secret, data_value.encode("utf-8"))
    except Exception as exc:
        print(f"[GROUND] 400 Failed building encrypted packet: {exc}")
        return jsonify({
            "error": "Failed building encrypted packet",
            "details": str(exc),
        }), 400

    tx_id = int(time.time() * 1000)

    # Register transaction with ledger and mine so the router verification step succeeds.
    ledger_body = {
        "transaction_id": tx_id,
        "transaction_hash": transaction_hash,
        "legacy_signature": signature,
        "signing_public_key": PUBLIC_KEY_HEX,
    }
    try:
        ledger_post = requests.post("http://127.0.0.1:5003/transaction/new", json=ledger_body, timeout=3)
        if ledger_post.status_code not in (200, 201):
            print(f"[GROUND] 400 Ledger rejected transaction: {ledger_post.status_code} {ledger_post.text}")
            return jsonify({
                "error": "Ledger rejected transaction",
                "status_code": ledger_post.status_code,
                "ledger_response": ledger_post.text,
            }), 400
        mine_resp = requests.get("http://127.0.0.1:5003/mine", timeout=5)
        if mine_resp.status_code not in (200, 201):
            print(f"[GROUND] 400 Ledger mining failed: {mine_resp.status_code} {mine_resp.text}")
            return jsonify({
                "error": "Ledger mining failed",
                "status_code": mine_resp.status_code,
                "ledger_response": mine_resp.text,
            }), 400
    except requests.exceptions.RequestException as exc:
        print(f"[GROUND] 400 Ledger operation failed while calling http://127.0.0.1:5003/transaction/new or http://127.0.0.1:5003/mine: {exc}")
        return jsonify({
            "error": "Ledger operation failed",
            "details": str(exc),
        }), 400

    relay_body = {
        "payload": {
            "data": data_value,
            "destination": destination,
            "intercept": bool(intercept_enabled),
            "encrypted_payload": encrypted["ciphertext"],
            "cipher_meta": {
                "nonce": encrypted["nonce"],
                "tag": encrypted["tag"],
            },
            "ciphertext_token": ciphertext_token.hex(),
            "transaction_hash": transaction_hash,
            "transaction_id": tx_id,
            "legacy_signing_public_key": PUBLIC_KEY_HEX,
        },
        "metadata": {
            "legacy_ecdsa_signature": signature,
            "transaction_hash": transaction_hash,
            "signing_public_key": PUBLIC_KEY_HEX,
        },
    }

    print(f"[GROUND] Relay URL: {SATELLITE_RELAY_URL}")
    print(f"[GROUND] Relay payload: {relay_body}")

    # Phase 3 forwarding: best-effort forward to the satellite relay.
    # Ground station must continue operating even if relay is unavailable.
    relay_url = "http://127.0.0.1:5001/relay"
    print("[Ground Station] Forwarding packet to Satellite Relay...")
    relay_payload_size = _payload_size_bytes(relay_body)
    relay_start = time.perf_counter()
    try:
        forward_resp = requests.post(relay_url, json=relay_body, timeout=5)
        relay_latency_ms = round((time.perf_counter() - relay_start) * 1000, 2)
        _log_packet_event(
            incoming_endpoint="/broadcast",
            destination_endpoint=relay_url,
            payload_size_bytes=relay_payload_size,
            http_status_code=forward_resp.status_code,
            forwarding_succeeded=forward_resp.ok,
            forwarding_failed=not forward_resp.ok,
            relay_latency_ms=relay_latency_ms,
            packet_dropped=False,
        )
        if forward_resp.ok:
            print("[Ground Station] Successfully forwarded to Satellite Relay.")
        else:
            print(
                "[Ground Station] Relay forwarding returned non-success: "
                f"status={forward_resp.status_code}, body={forward_resp.text}"
            )
    except requests.exceptions.RequestException as e:
        relay_latency_ms = round((time.perf_counter() - relay_start) * 1000, 2)
        _log_packet_event(
            incoming_endpoint="/broadcast",
            destination_endpoint=relay_url,
            payload_size_bytes=relay_payload_size,
            http_status_code="N/A",
            forwarding_succeeded=False,
            forwarding_failed=True,
            relay_latency_ms=relay_latency_ms,
            packet_dropped=False,
        )
        print(f"[Ground Station] Relay forwarding failed to {relay_url}: {e}")

    return jsonify(
        {
            "status": "success",
            "message": "Broadcast propagated",
            "satellite_relay_url": SATELLITE_RELAY_URL,
            "transaction_hash": transaction_hash,
        }
    ), 200


@app.route("/health", methods=["GET"])
def health() -> Any:
    """Health check endpoint for dashboard and service monitors."""
    return jsonify({"status": "healthy"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
