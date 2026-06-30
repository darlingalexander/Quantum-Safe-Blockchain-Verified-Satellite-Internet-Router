import json
import os
from typing import Any, Dict

import requests
from ecdsa import SECP256k1, SigningKey
from flask import Flask, jsonify, request

from src.common.crypto_utils import compute_sha256_hex_digest


app = Flask(__name__)

SATELLITE_RELAY_URL = os.getenv(
    "SATELLITE_RELAY_URL", "http://127.0.0.1:5001/relay"
)
ECDSA_PRIVATE_KEY_HEX = os.getenv("GROUND_STATION_ECDSA_PRIVKEY_HEX")


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


@app.route("/broadcast", methods=["POST"])
def broadcast() -> Any:
    """Receive a transaction payload, sign and hash it, then relay to satellite."""
    try:
        incoming = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "Invalid JSON payload"}), 400

    if not isinstance(incoming, dict):
        return jsonify({"error": "Payload must be a JSON object"}), 400

    # Normalize supported shapes:
    # - { "payload": { ... } }
    # - { "data": "...", "url": "..." }
    # - or the transaction dict directly
    if "payload" in incoming and isinstance(incoming["payload"], dict):
        payload = incoming["payload"]
    else:
        payload = incoming

    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    transaction_hash = build_transaction_hash(payload)
    signature = generate_ecdsa_signature(payload_bytes)

    relay_body = {
        "payload": payload,
        "metadata": {
            "legacy_ecdsa_signature": signature,
            "transaction_hash": transaction_hash,
            "signing_public_key": PUBLIC_KEY_HEX,
        },
    }

    # Forward to the satellite relay and handle errors cleanly
    try:
        resp = requests.post(
            SATELLITE_RELAY_URL,
            json=relay_body,
            timeout=5,
        )
    except requests.exceptions.Timeout as exc:
        return jsonify({
            "error": "Satellite relay request timed out",
            "satellite_relay_url": SATELLITE_RELAY_URL,
            "details": str(exc),
        }), 504
    except requests.exceptions.ConnectionError as exc:
        return jsonify({
            "error": "Could not connect to satellite relay",
            "satellite_relay_url": SATELLITE_RELAY_URL,
            "details": str(exc),
        }), 502
    except requests.RequestException as exc:
        return jsonify({
            "error": "Error sending request to satellite relay",
            "satellite_relay_url": SATELLITE_RELAY_URL,
            "details": str(exc),
        }), 502

    # Surface descriptive downstream errors if the satellite relay replies with non-2xx
    if not resp.ok:
        try:
            satellite_body = resp.json()
        except Exception:
            satellite_body = resp.text
        return jsonify({
            "error": "Satellite relay returned non-success status",
            "satellite_relay_url": SATELLITE_RELAY_URL,
            "satellite_status_code": resp.status_code,
            "satellite_response": satellite_body,
        }), resp.status_code

    return jsonify(
        {
            "status": "success",
            "message": "Broadcast propagated",
            "satellite_relay_url": SATELLITE_RELAY_URL,
            "transaction_hash": transaction_hash,
        }
    ), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
