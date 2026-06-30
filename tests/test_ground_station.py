"""
Tests for the ground station gateway POST /payload endpoint.
"""

import json
from src.ground_station.gateway import app


def test_payload_endpoint_returns_expected_fields():
    client = app.test_client()
    payload = {"data": "test message", "url": "http://localhost:5001"}
    resp = client.post('/payload', json=payload)
    assert resp.status_code == 200
    j = resp.get_json()
    assert isinstance(j, dict)

    # Basic response fields
    assert j.get('status') == 'ok'
    assert 'transaction_hash' in j
    assert 'transaction_id' in j

    # The gateway returns a packet to the destination during processing; however
    # this test verifies the response contains the transaction hash and id. We also
    # check that the ledger transaction hash looks like a valid SHA-256 hex string.
    tx_hash = j['transaction_hash']
    assert isinstance(tx_hash, str)
    assert len(tx_hash) == 64
    assert all(c in '0123456789abcdef' for c in tx_hash)


if __name__ == '__main__':
    # Quick local run
    test_payload_endpoint_returns_expected_fields()
    print('ok')
