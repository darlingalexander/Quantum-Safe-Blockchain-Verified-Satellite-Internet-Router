#!/usr/bin/env python3
"""Adversary SDR node that intercepts, tampers, and forwards encrypted packets."""

import logging
from typing import Any, Dict, Tuple

import requests
from flask import Flask, jsonify, request


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
LOG = logging.getLogger(__name__)

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

ROUTER_RECEIVE_URL = "http://127.0.0.1:5002/receive"


attack_stats = {
    "packets_intercepted": 0,
    "packets_tampered": 0,
    "packets_forwarded": 0,
    "forward_failures": 0,
}


def _normalize_packet_shape(packet: Dict[str, Any]) -> Dict[str, Any]:
    """Accept relay-compatible nested packets and normalize to flat router shape."""
    if not isinstance(packet, dict):
        return {}

    if "payload" in packet and "metadata" in packet:
        payload = packet.get("payload") or {}
        metadata = packet.get("metadata") or {}
        flat: Dict[str, Any] = {}
        if isinstance(payload, dict):
            flat.update(payload)
        if isinstance(metadata, dict):
            for key, value in metadata.items():
                if key not in flat:
                    flat[key] = value
        return flat

    return dict(packet)


def _tamper_ciphertext_hex(ciphertext_hex: str) -> Tuple[str, bool]:
    """Flip one hex nibble to simulate realistic SDR in-transit corruption."""
    if not isinstance(ciphertext_hex, str) or len(ciphertext_hex) < 2:
        return ciphertext_hex, False

    chars = list(ciphertext_hex)
    index = min(10, len(chars) - 1)
    original = chars[index].lower()

    if original in ("0", "1", "2", "3", "4", "5", "6", "7"):
        chars[index] = "f"
    else:
        chars[index] = "0"

    return "".join(chars), chars[index].lower() != original

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy"}), 200

@app.route("/intercept", methods=["POST"])
def intercept() -> Any:
    if not request.is_json:
        return jsonify({"status": "error", "message": "Content-Type must be application/json"}), 400

    try:
        incoming = request.get_json(force=True)
    except Exception as exc:
        LOG.error("Failed to parse JSON: %s", exc)
        return jsonify({"status": "error", "message": "Invalid JSON payload"}), 400

    if not isinstance(incoming, dict):
        return jsonify({"status": "error", "message": "Payload must be a JSON object"}), 400

    attack_stats["packets_intercepted"] += 1
    packet = _normalize_packet_shape(incoming)

    tx_id = packet.get("transaction_id", "UNKNOWN")
    tx_hash = packet.get("transaction_hash", "UNKNOWN")

    ciphertext_hex = packet.get("encrypted_payload")
    tampered_ciphertext, did_tamper = _tamper_ciphertext_hex(ciphertext_hex)
    if not did_tamper:
        LOG.warning("Could not tamper encrypted payload for tx_id=%s", tx_id)
        return jsonify({
            "status": "error",
            "message": "Packet missing usable encrypted_payload for SDR tampering",
            "transaction_id": tx_id,
            "transaction_hash": tx_hash,
        }), 400

    packet["encrypted_payload"] = tampered_ciphertext
    attack_stats["packets_tampered"] += 1

    LOG.warning(
        "[ADVERSARY] Tampered packet in transit: tx_id=%s tx_hash=%.8s",
        tx_id,
        str(tx_hash),
    )

    try:
        forward_resp = requests.post(ROUTER_RECEIVE_URL, json=packet, timeout=5)
        attack_stats["packets_forwarded"] += 1
        response_payload: Dict[str, Any]
        try:
            response_payload = forward_resp.json()
        except ValueError:
            response_payload = {"raw": forward_resp.text}

        return jsonify({
            "status": "intercepted",
            "tampered": True,
            "forwarded_to": ROUTER_RECEIVE_URL,
            "transaction_id": tx_id,
            "transaction_hash": tx_hash,
            "router_status": forward_resp.status_code,
            "router_response": response_payload,
            "attack_stats": attack_stats,
        }), 200
    except requests.RequestException as exc:
        attack_stats["forward_failures"] += 1
        LOG.error("Forward to router failed for tx_id=%s: %s", tx_id, exc)
        return jsonify({
            "status": "intercepted",
            "tampered": True,
            "forwarded_to": ROUTER_RECEIVE_URL,
            "transaction_id": tx_id,
            "transaction_hash": tx_hash,
            "forwarding_error": str(exc),
            "attack_stats": attack_stats,
        }), 502


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5004, debug=True)
