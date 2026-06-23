#!/usr/bin/env python3
"""
Tests for the Immutable Verification Ledger.

- Test Case 1: Submit a valid transaction, mine a block, and verify chain linkage.
- Test Case 2: Submit an invalid signature payload and verify the ledger rejects it.
"""

import json

import pytest

from src.blockchain import ledger as ledger_module
from src.blockchain.ledger import app
from src.common.legacy_crypto import get_public_key_hex, sign_ecdsa
from src.common.crypto_utils import compute_sha256


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


@pytest.fixture(autouse=True)
def reset_ledger_state():
    """Reset the in-memory ledger state before each test."""
    with ledger_module.chain_lock:
        genesis = ledger_module._create_genesis_block()
        ledger_module.chain.clear()
        ledger_module.chain.append(genesis)
        ledger_module.pending_transactions.clear()
    yield
    with ledger_module.chain_lock:
        ledger_module.chain.clear()
        ledger_module.chain.append(ledger_module._create_genesis_block())
        ledger_module.pending_transactions.clear()


def _make_valid_transaction_payload(tx_id: int, data: str):
    data_hash = compute_sha256(data)
    signature = sign_ecdsa(data_hash.encode("utf-8")).hex()
    return {
        "transaction_id": tx_id,
        "transaction_hash": data_hash,
        "legacy_signature": signature,
        "signing_public_key": get_public_key_hex(),
    }


class TestImmutableLedger:
    def test_valid_transaction_can_be_mined_and_linked(self, client):
        payload = _make_valid_transaction_payload(1, "valid blockchain payload")

        response = client.post(
            "/transaction/new",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert response.status_code == 201
        assert response.json["status"] == "accepted"
        assert response.json["transaction_id"] == 1

        mine_response = client.get("/mine")
        assert mine_response.status_code == 201
        assert mine_response.json["status"] == "mined"
        assert mine_response.json["tx_count"] == 1

        chain_response = client.get("/chain")
        assert chain_response.status_code == 200
        chain_body = chain_response.json
        assert chain_body["length"] == 2
        block = chain_body["chain"][1]
        assert block["previous_hash"] == chain_body["chain"][0]["hash"]
        assert len(block["transactions"]) == 1
        assert block["transactions"][0]["transaction_id"] == 1
        assert block["transactions"][0]["transaction_hash"] == payload["transaction_hash"]

    def test_invalid_signature_rejected_and_not_mined(self, client):
        payload = {
            "transaction_id": 2,
            "transaction_hash": compute_sha256("unsigned payload"),
            "legacy_signature": "deadbeef",
            "signing_public_key": get_public_key_hex(),
        }

        response = client.post(
            "/transaction/new",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert response.status_code == 400
        assert response.json["status"] == "error"
        assert "transaction_id" not in response.json or response.json["status"] != "accepted"

        mine_response = client.get("/mine")
        assert mine_response.status_code == 200
        assert mine_response.json["status"] == "idle"
        assert "tx_count" not in mine_response.json or mine_response.json["tx_count"] == 0
