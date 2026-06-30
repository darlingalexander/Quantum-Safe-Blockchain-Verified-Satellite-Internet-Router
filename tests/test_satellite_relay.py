#!/usr/bin/env python3
"""
Tests for satellite relay node.
"""

import pytest
import json
from unittest.mock import patch, MagicMock
from src.satellite.relay import app, relay_stats


@pytest.fixture
def client():
    """Create a Flask test client."""
    app.config["TESTING"] = True
    with app.test_client() as client:
        # Reset stats before each test
        relay_stats["total_packets_received"] = 0
        relay_stats["packets_forwarded"] = 0
        relay_stats["packets_dropped"] = 0
        relay_stats["forwarding_failures"] = 0
        yield client


@pytest.fixture
def sample_packet():
    """Create a sample unified JSON packet."""
    return {
        "data": "test blockchain transaction",
        "encrypted_payload": "encrypted_data_hex",
        "cipher_meta": {
            "nonce": "abc123",
            "tag": "def456",
        },
        "ciphertext_token": "token123",
        "transaction_hash": "a" * 64,
        "transaction_id": 1,
        "legacy_ecdsa_signature": "signature_hex",
        "legacy_signing_public_key": "pubkey_hex",
        "destination": "http://localhost:5002",
    }


class TestRelayEndpoint:
    """Test POST /relay endpoint."""

    def test_relay_accepts_valid_packet(self, client, sample_packet):
        """Verify relay accepts valid JSON packet."""
        with patch("src.satellite.relay.requests.post") as mock_post:
            with patch("src.satellite.relay.random.random", return_value=0.5):
                mock_post.return_value = MagicMock(status_code=200)
                response = client.post(
                    "/relay",
                    data=json.dumps(sample_packet),
                    content_type="application/json",
                )
                assert response.status_code == 200
                assert response.json["status"] == "relayed"
                assert response.json["transaction_id"] == 1

    def test_relay_rejects_non_json(self, client):
        """Verify relay rejects non-JSON content."""
        response = client.post(
            "/relay",
            data="not json",
            content_type="text/plain",
        )
        assert response.status_code == 400
        assert "application/json" in response.json["message"]

    def test_relay_drops_packet_based_on_rate(self, client, sample_packet):
        """Verify relay drops packets based on PACKET_DROP_RATE."""
        with patch("src.satellite.relay.random.random", return_value=0.01):  # Below 0.02 drop rate
            response = client.post(
                "/relay",
                data=json.dumps(sample_packet),
                content_type="application/json",
            )
            assert response.status_code == 408
            assert response.json["status"] == "dropped"

    def test_relay_survives_packet_drop_roll(self, client, sample_packet):
        """Verify relay survives packet when drop roll exceeds threshold."""
        with patch("requests.post") as mock_post:
            with patch("src.satellite.relay.random.random", return_value=0.05):  # Above 0.02 drop rate
                mock_post.return_value = MagicMock(status_code=200)
                response = client.post(
                    "/relay",
                    data=json.dumps(sample_packet),
                    content_type="application/json",
                )
                assert response.status_code == 200
                assert response.json["status"] == "relayed"

    def test_relay_forwards_to_router_endpoint(self, client, sample_packet):
        """Verify relay forwards packet to router endpoint."""
        with patch("src.satellite.relay.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            client.post(
                "/relay",
                data=json.dumps(sample_packet),
                content_type="application/json",
            )
            mock_post.assert_called_once()
            call_args = mock_post.call_args
            assert "localhost:5002/receive" in call_args[0][0]

    def test_relay_handles_router_timeout(self, client, sample_packet):
        """Verify relay handles router timeout gracefully."""
        import requests
        with patch("src.satellite.relay.requests.post", side_effect=requests.Timeout):
            with patch("src.satellite.relay.random.random", return_value=0.5):
                response = client.post(
                    "/relay",
                    data=json.dumps(sample_packet),
                    content_type="application/json",
                )
                assert response.status_code == 504
                assert response.json["status"] == "forwarding_timeout"

    def test_relay_handles_router_connection_error(self, client, sample_packet):
        """Verify relay handles router connection error gracefully."""
        import requests
        with patch("src.satellite.relay.requests.post", side_effect=requests.ConnectionError):
            with patch("src.satellite.relay.random.random", return_value=0.5):
                response = client.post(
                    "/relay",
                    data=json.dumps(sample_packet),
                    content_type="application/json",
                )
                assert response.status_code == 502
                assert response.json["status"] == "forwarding_connection_error"

    def test_relay_increments_statistics(self, client, sample_packet):
        """Verify relay increments statistics correctly."""
        with patch("src.satellite.relay.requests.post") as mock_post:
            with patch("src.satellite.relay.random.random", return_value=0.5):
                mock_post.return_value = MagicMock(status_code=200)
                
                # Send two packets
                client.post(
                    "/relay",
                    data=json.dumps(sample_packet),
                    content_type="application/json",
                )
                client.post(
                    "/relay",
                    data=json.dumps(sample_packet),
                    content_type="application/json",
                )
                
                assert relay_stats["total_packets_received"] == 2
                assert relay_stats["packets_forwarded"] == 2


class TestRelayStats:
    """Test GET /stats endpoint."""

    def test_stats_endpoint_returns_counters(self, client):
        """Verify /stats endpoint returns relay statistics."""
        response = client.get("/stats")
        assert response.status_code == 200
        data = response.json
        assert "total_packets_received" in data
        assert "packets_forwarded" in data
        assert "packets_dropped" in data
        assert "forwarding_failures" in data


class TestRelayHealth:
    """Test GET /health endpoint."""

    def test_health_check_returns_healthy(self, client):
        """Verify /health endpoint returns healthy status."""
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json["status"] == "healthy"
