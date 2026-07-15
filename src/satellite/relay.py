#!/usr/bin/env python3
"""
Simulated LEO Satellite Relay Node.

Acts as a pass-through relay with configurable network degradation:
- Orbital latency simulation (45ms LEO round-trip default)
- Packet drop rate simulation (2% atmospheric attenuation default)

Accepts unified JSON packets from ground station gateway and forwards to router node.
"""

import time
import random
import logging
from flask import Flask, request, jsonify
import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# Configurable network degradation parameters
ORBITAL_LATENCY_SECS = 0.045  # 45ms LEO round-trip delay
PACKET_DROP_RATE = 0.02       # 2% packet loss due to atmospheric attenuation

# Downstream router node endpoint
ROUTER_NODE_ENDPOINT = "http://localhost:5002/receive"
ADVERSARY_SDR_ENDPOINT = "http://127.0.0.1:5004/intercept"

# Flask app initialization
app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

# In-memory relay statistics
relay_stats = {
    "total_packets_received": 0,
    "packets_forwarded": 0,
    "packets_dropped": 0,
    "forwarding_failures": 0,
}


def _payload_size_bytes(payload):
    try:
        return len(request.get_data(cache=True) if request else b"")
    except Exception:
        return -1


def _log_packet_event(
    *,
    incoming_endpoint,
    destination_endpoint,
    payload_size_bytes,
    http_status_code,
    forwarding_succeeded,
    forwarding_failed,
    relay_latency_ms,
    packet_dropped,
):
    logger.info(
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


# Make sure these imports are at the very top of your src/satellite/relay.py file
import time
import random

# Place these configurations near the top of the file as well
ORBITAL_LATENCY_SECS = 0.150  # 150ms transit delay simulation
PACKET_DROP_RATE = 0.10       # 10% simulated signal loss packet drop

# REPLACE YOUR OLD @app.route("/relay") BLOCK WITH THIS ONE:
@app.route("/relay", methods=["POST"])
def relay_packet():
    """
    POST /relay - Accept unified JSON packet from ground station, apply network degradation,
    and forward to router node.
    
    Expected payload: JSON packet with structure:
    {
        "data": str,
        "encrypted_payload": bytes,
        "cipher_meta": {...},
        "transaction_hash": str (64-char hex SHA-256),
        "transaction_id": int,
        "legacy_ecdsa_signature": bytes,
        "legacy_signing_public_key": str,
        "destination": str
    }
    """
    try:
        packet = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "Bad packet shape reaching space link"}), 400

    payload_size_bytes = _payload_size_bytes(packet)
    _log_packet_event(
        incoming_endpoint="/relay",
        destination_endpoint="N/A",
        payload_size_bytes=payload_size_bytes,
        http_status_code="N/A",
        forwarding_succeeded=False,
        forwarding_failed=False,
        relay_latency_ms="N/A",
        packet_dropped=False,
    )

    print("[Relay] Packet received.")

    # Verify request has JSON data
    if not request.is_json:
        logger.warning("[RELAY] Rejected non-JSON request from %s", request.remote_addr)
        return jsonify({"status": "error", "message": "Content-Type must be application/json"}), 400
    
    # Normalize packet shapes: accept both flattened packets and
    # nested {"payload": {...}, "metadata": {...}} shapes produced by
    # different gateway endpoints. Flatten into expected top-level fields.
    if isinstance(packet, dict) and "payload" in packet and "metadata" in packet:
        try:
            nested_payload = packet.get("payload") or {}
            nested_meta = packet.get("metadata") or {}
            # Create a flattened packet merging payload and metadata
            flat = {}
            if isinstance(nested_payload, dict):
                flat.update(nested_payload)
            # metadata keys should not overwrite payload unless absent
            for k, v in nested_meta.items():
                if k not in flat:
                    flat[k] = v
            packet = flat
            logger.info("[RELAY] Normalized nested payload/metadata into flat packet")
        except Exception:
            logger.exception("[RELAY] Failed to normalize nested packet shape")
    relay_stats["total_packets_received"] += 1
    
    # Extract packet identifiers for logging
    tx_id = packet.get("transaction_id", "UNKNOWN")
    tx_hash = packet.get("transaction_hash", "UNKNOWN")
    
    logger.info(
        "[RELAY] Packet entry: tx_id=%s, tx_hash=%.8s, from_addr=%s",
        tx_id, tx_hash, request.remote_addr
    )

    intercept_flag = packet.get("intercept", False)
    if isinstance(intercept_flag, str):
        intercept_flag = intercept_flag.strip().lower() in ("1", "true", "yes", "on")

    forward_endpoint = ADVERSARY_SDR_ENDPOINT if intercept_flag else "http://127.0.0.1:5002/receive"
    logger.info(
        "[RELAY] Routing mode: %s (forward_endpoint=%s)",
        "ATTACK" if intercept_flag else "NORMAL",
        forward_endpoint,
    )
    
    # Simulate orbital propagation latency
    print("[Relay] Applying orbital latency...")
    latency_start = time.perf_counter()
    logger.info("[RELAY] Applying orbital latency: %.1f ms (%.3f sec)", ORBITAL_LATENCY_SECS * 1000, ORBITAL_LATENCY_SECS)
    time.sleep(ORBITAL_LATENCY_SECS)
    relay_latency_ms = round((time.perf_counter() - latency_start) * 1000, 2)
    
    # Determine if packet is dropped due to atmospheric attenuation
    drop_roll = random.random()
    is_dropped = drop_roll < PACKET_DROP_RATE
    
    logger.info(
        "[RELAY] Drop verdict: roll=%.4f, threshold=%.4f, status=%s",
        drop_roll, PACKET_DROP_RATE, "DROPPED" if is_dropped else "SURVIVES"
    )
    
    if is_dropped:
        relay_stats["packets_dropped"] += 1
        print("[Relay] Packet dropped.")
        _log_packet_event(
            incoming_endpoint="/relay",
            destination_endpoint=forward_endpoint,
            payload_size_bytes=payload_size_bytes,
            http_status_code=200,
            forwarding_succeeded=False,
            forwarding_failed=False,
            relay_latency_ms=relay_latency_ms,
            packet_dropped=True,
        )
        return jsonify({
            "status": "dropped",
            "transaction_id": tx_id,
            "transaction_hash": tx_hash,
        }), 200
    
    # Packet survives: forward to router node
    router_endpoint = forward_endpoint

    logger.info(
        "[RELAY] Forwarding packet downstream: %s (tx_id=%s, tx_hash=%.8s)",
        router_endpoint, tx_id, tx_hash
    )
    
    try:
        response = requests.post(
            router_endpoint,
            json=packet,
            timeout=5,
        )

        _log_packet_event(
            incoming_endpoint="/relay",
            destination_endpoint=router_endpoint,
            payload_size_bytes=payload_size_bytes,
            http_status_code=response.status_code,
            forwarding_succeeded=response.status_code == 200,
            forwarding_failed=response.status_code != 200,
            relay_latency_ms=relay_latency_ms,
            packet_dropped=False,
        )
        
        if response.status_code == 200:
            relay_stats["packets_forwarded"] += 1
            print("[Relay] Forward successful.")
            print("[Relay] Packet forwarded to Home Router.")
            logger.info(
                "[RELAY] Forwarding success: tx_id=%s, router_status=%s",
                tx_id, response.status_code
            )
            return jsonify({
                "status": "relayed",
                "message": "Packet forwarded to router node",
                "transaction_id": tx_id,
                "transaction_hash": tx_hash,
                "router_status": response.status_code,
            }), 200
        else:
            relay_stats["forwarding_failures"] += 1
            logger.error(
                "[RELAY] Forwarding received non-200 response: tx_id=%s, router_status=%s",
                tx_id, response.status_code
            )
            return jsonify({
                "status": "forwarding_error",
                "message": f"Router returned status {response.status_code}",
                "transaction_id": tx_id,
                "transaction_hash": tx_hash,
                "router_status": response.status_code,
            }), response.status_code
    
    except requests.Timeout:
        relay_stats["forwarding_failures"] += 1
        print("[Relay] Forward failed.")
        _log_packet_event(
            incoming_endpoint="/relay",
            destination_endpoint=router_endpoint,
            payload_size_bytes=payload_size_bytes,
            http_status_code=504,
            forwarding_succeeded=False,
            forwarding_failed=True,
            relay_latency_ms=relay_latency_ms,
            packet_dropped=False,
        )
        logger.error(
            "[RELAY] Forwarding timeout: tx_id=%s, endpoint=%s",
            tx_id, router_endpoint
        )
        return jsonify({
            "status": "forwarding_timeout",
            "message": "Router node did not respond in time",
            "transaction_id": tx_id,
            "transaction_hash": tx_hash,
        }), 504
    
    except requests.exceptions.ConnectionError as e:
        relay_stats["forwarding_failures"] += 1
        print("[Relay] Forward failed.")
        print(f"[Relay] Forward failed to {router_endpoint}: {e}")
        _log_packet_event(
            incoming_endpoint="/relay",
            destination_endpoint=router_endpoint,
            payload_size_bytes=payload_size_bytes,
            http_status_code=502,
            forwarding_succeeded=False,
            forwarding_failed=True,
            relay_latency_ms=relay_latency_ms,
            packet_dropped=False,
        )
        logger.error(
            "[RELAY] Forwarding connection error: tx_id=%s, endpoint=%s, error=%s",
            tx_id, router_endpoint, str(e)
        )
        return jsonify({
            "status": "forwarding_connection_error",
            "message": "Cannot reach router node",
            "transaction_id": tx_id,
            "transaction_hash": tx_hash,
        }), 502
    
    except requests.exceptions.RequestException as e:
        relay_stats["forwarding_failures"] += 1
        print("[Relay] Forward failed.")
        print(f"[Relay] Forward failed to {router_endpoint}: {e}")
        _log_packet_event(
            incoming_endpoint="/relay",
            destination_endpoint=router_endpoint,
            payload_size_bytes=payload_size_bytes,
            http_status_code=502,
            forwarding_succeeded=False,
            forwarding_failed=True,
            relay_latency_ms=relay_latency_ms,
            packet_dropped=False,
        )
        logger.error(
            "[RELAY] Forwarding request error: tx_id=%s, endpoint=%s, error=%s",
            tx_id, router_endpoint, str(e)
        )
        return jsonify({
            "status": "forwarding_error",
            "message": "Error forwarding packet to router",
            "transaction_id": tx_id,
            "transaction_hash": tx_hash,
        }), 502


@app.route("/stats", methods=["GET"])
def get_stats():
    """
    GET /stats - Retrieve relay statistics.
    
    Returns:
        JSON object with packet counts: received, forwarded, dropped, failed.
    """
    logger.info("[RELAY] Stats request from %s", request.remote_addr)
    return jsonify({
        "total_packets_received": relay_stats["total_packets_received"],
        "packets_forwarded": relay_stats["packets_forwarded"],
        "packets_dropped": relay_stats["packets_dropped"],
        "forwarding_failures": relay_stats["forwarding_failures"],
    }), 200


@app.route("/health", methods=["GET"])
def health_check():
    """
    GET /health - Health check endpoint.
    
    Returns:
        200 OK with status message.
    """
    return jsonify({"status": "healthy"}), 200


if __name__ == "__main__":
    logger.info("=" * 80)
    logger.info("LEO Satellite Relay Node starting on port 5001")
    logger.info("Orbital latency: %.1f ms", ORBITAL_LATENCY_SECS * 1000)
    logger.info("Packet drop rate: %.1f %%", PACKET_DROP_RATE * 100)
    logger.info("Router endpoint: %s", ROUTER_NODE_ENDPOINT)
    logger.info("=" * 80)
    app.run(host="0.0.0.0", port=5001, debug=False)
