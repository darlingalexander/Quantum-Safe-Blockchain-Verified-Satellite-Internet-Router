#!/usr/bin/env python3
"""Simulated Adversary SDR Node for intercepting and tampering with packets."""

import logging
import os
from typing import Any, Dict

from flask import Flask, jsonify, request


APP_DIR = os.path.dirname(__file__)
HARVEST_FILE = os.path.join(APP_DIR, "harvested_vault.txt")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
LOGGER = logging.getLogger("sdr_attacker")

app = Flask(__name__)


def _append_harvest(entry: str) -> None:
    """Persist an intercepted packet summary into the local vault file."""
    with open(HARVEST_FILE, "a", encoding="utf-8") as handle:
        handle.write(entry + "\n")


@app.route("/intercept", methods=["POST"])
def intercept_packet() -> Any:
    """Intercept a packet, log it, harvest the payload, and simulate tampering."""
    if not request.is_json:
        LOGGER.warning("Received non-JSON request to /intercept")
        return jsonify({"status": "error", "message": "Content-Type must be application/json"}), 400

    try:
        packet = request.get_json(force=True)
    except Exception as exc:
        LOGGER.exception("Failed to parse JSON payload: %s", exc)
        return jsonify({"status": "error", "message": "Invalid JSON payload"}), 400

    if not isinstance(packet, dict):
        LOGGER.warning("Rejected non-object packet payload")
        return jsonify({"status": "error", "message": "Payload must be a JSON object"}), 400

    payload = packet.get("payload")
    metadata = packet.get("metadata", {})

    LOGGER.info("Intercepted packet at adversary node")
    LOGGER.info("Packet keys: %s", sorted(packet.keys()))

    if isinstance(payload, dict):
        payload_text = payload.get("data")
        if isinstance(payload_text, str):
            LOGGER.info("Captured plaintext payload: %s", payload_text)
        else:
            LOGGER.warning("Payload did not contain string data")
            payload_text = ""
    else:
        payload_text = str(payload) if payload is not None else ""

    harvest_entry = {
        "payload": payload_text,
        "metadata": metadata,
    }
    _append_harvest(str(harvest_entry))
    LOGGER.info("Harvested packet into %s", HARVEST_FILE)

    if isinstance(payload, dict) and isinstance(payload.get("data"), str):
        tampered_payload = payload_text.replace("quantum", "tampered")
        payload["data"] = tampered_payload
        LOGGER.warning("Spoofing module modified payload text: %s", tampered_payload)
        LOGGER.warning("Metadata hashes preserved during tampering attack")
        LOGGER.info("Tampering simulation complete; metadata remains unchanged")
    else:
        LOGGER.warning("Unable to spoof payload text; payload structure unsupported")

    return jsonify(
        {
            "status": "intercepted",
            "tampered": True,
            "harvested": True,
            "payload": payload,
            "metadata": metadata,
        }
    ), 200


if __name__ == "__main__":
    LOGGER.info("Adversary SDR Node starting on port 5004")
    app.run(host="0.0.0.0", port=5004, debug=False)
