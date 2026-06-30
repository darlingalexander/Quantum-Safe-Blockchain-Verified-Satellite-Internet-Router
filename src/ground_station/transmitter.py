"""
Simple transmitter utility to send prepared packets to the satellite relay.

This script provides a `send_packet` function that posts a JSON packet to the
satellite relay and handles network errors gracefully.
"""
import json
import logging
from typing import Dict, Any, Optional

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError


SATELLITE_RELAY = "http://127.0.0.1:5001/relay"
LOG = logging.getLogger(__name__)


def send_packet(packet: Dict[str, Any], url: Optional[str] = None, timeout: float = 5.0) -> Dict[str, Any]:
    """Send a JSON packet to the satellite relay.

    Args:
        packet: The JSON-serializable packet to send.
        url: Optional target URL. Defaults to `SATELLITE_RELAY`.
        timeout: Request timeout in seconds.

    Returns:
        A dict containing `status` and additional information.
    """
    target = url or SATELLITE_RELAY
    LOG.info("Sending packet to %s", target)

    try:
        resp = requests.post(target, json=packet, timeout=timeout)
        resp.raise_for_status()
        LOG.info("Packet delivered successfully: %s", resp.status_code)
        return {"status": "delivered", "code": resp.status_code, "response": resp.text}

    except Timeout as exc:
        LOG.warning("Timeout while sending packet to %s: %s", target, exc)
        return {"status": "timeout", "error": str(exc)}

    except ConnectionError as exc:
        LOG.warning("Connection error while sending packet to %s: %s", target, exc)
        return {"status": "connection_error", "error": str(exc)}

    except RequestException as exc:
        # Catch all other requests exceptions
        LOG.error("Failed to send packet to %s: %s", target, exc)
        return {"status": "error", "error": str(exc)}


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sample_packet = {
        "transaction_hash": "deadbeef",
        "transaction_id": 1,
        "payload": "...",
    }
    result = send_packet(sample_packet)
    print(result)
