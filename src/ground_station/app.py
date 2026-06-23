import json
import os
from typing import Any, Dict

import requests
from ecdsa import SECP256k1, SigningKey
from flask import Flask, jsonify, request

from src.common.crypto_utils import compute_sha256


app = Flask(__name__)

SATELLITE_RELAY_URL = os.getenv(
    "SATELLITE_RELAY_URL", "http://localhost:5001/relay"
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
    return compute_sha256(canonical)


@app.route("/broadcast", methods=["POST"])
def broadcast() -> Any:
    """Receive a transaction payload, sign and hash it, then relay to satellite."""
    try:
        payload = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "Invalid JSON payload"}), 400

    if not isinstance(payload, dict):
        return jsonify({"error": "Payload must be a JSON object"}), 400

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

    try:
        response = requests.post(
            SATELLITE_RELAY_URL,
            json=relay_body,
            timeout=5,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        return (
            jsonify(
                {
                    "error": "Failed to deliver broadcast to satellite relay",
                    "details": str(exc),
                }
            ),
            502,
        )

    return jsonify(
        {
            "status": "broadcast_sent",
            "satellite_relay_url": SATELLITE_RELAY_URL,
            "transaction_hash": transaction_hash,
            "legacy_ecdsa_signature": signature,
        }
    ), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
