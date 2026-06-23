#!/usr/bin/env python3
"""
Lightweight Immutable Verification Ledger (simulated)

Runs a Flask app on port 5003 exposing endpoints to submit transactions,
mine blocks, and verify transaction inclusion.
"""
import time
import json
import logging
import threading
from typing import List, Dict, Any, Optional
from hashlib import sha256

from flask import Flask, request, jsonify

from ecdsa import BadSignatureError, SECP256k1, VerifyingKey
from src.common.legacy_crypto import get_public_key_hex, sign_ecdsa
from src.common.legacy_crypto import LegacyCryptoError

LOG = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

chain_lock = threading.Lock()

# In-memory blockchain and pending transactions
chain: List[Dict[str, Any]] = []
pending_transactions: List[Dict[str, Any]] = []


def _hash_block(block: Dict[str, Any]) -> str:
    block_string = json.dumps(block, sort_keys=True).encode('utf-8')
    return sha256(block_string).hexdigest()


def _create_genesis_block():
    genesis = {
        "index": 0,
        "timestamp": time.time(),
        "transactions": [],
        "proof": 100,
        "previous_hash": "1",
    }
    genesis_hash = _hash_block(genesis)
    genesis["hash"] = genesis_hash
    return genesis


# Initialize chain with genesis
with chain_lock:
    chain.append(_create_genesis_block())


@app.route('/transaction/new', methods=['POST'])
def new_transaction():
    """Accept a new transaction after verifying the legacy ECDSA signature.

    Expected JSON body:
    {
        "transaction_id": int,
        "transaction_hash": str (sha256 hex),
        "legacy_signature": str (hex),
        "signing_public_key": str (hex)  # optional, but recommended
    }
    """
    if not request.is_json:
        LOG.warning("Rejecting non-JSON transaction submission")
        return jsonify({"status": "error", "message": "Content-Type must be application/json"}), 400

    data = request.get_json()
    tx_id = data.get('transaction_id')
    tx_hash = data.get('transaction_hash')
    legacy_sig = data.get('legacy_signature')
    signing_pubkey = data.get('signing_public_key')

    if tx_id is None or tx_hash is None or legacy_sig is None:
        LOG.error("Missing fields in transaction submission: %s", data)
        return jsonify({"status": "error", "message": "transaction_id, transaction_hash, legacy_signature required"}), 400

    # Verify signature using legacy_crypto
    try:
        sig_bytes = bytes.fromhex(legacy_sig) if isinstance(legacy_sig, str) else legacy_sig

        # Validate transaction_hash format
        if not (isinstance(tx_hash, str) and len(tx_hash) == 64):
            LOG.error("Invalid transaction_hash format: %s", tx_hash)
            return jsonify({"status": "error", "message": "Invalid transaction_hash format"}), 400

        # Verify signature if public key is available
        if signing_pubkey:
            pk_bytes = bytes.fromhex(signing_pubkey)
            vk = VerifyingKey.from_string(pk_bytes, curve=SECP256k1)
            vk.verify(sig_bytes, tx_hash.encode("utf-8"))
        else:
            if not isinstance(sig_bytes, (bytes, bytearray)):
                raise LegacyCryptoError("Signature is not bytes")

        pending = {
            "transaction_id": tx_id,
            "transaction_hash": tx_hash,
            "legacy_signature": legacy_sig,
            "signing_public_key": signing_pubkey,
            "timestamp": time.time(),
        }
        with chain_lock:
            pending_transactions.append(pending)
        LOG.info("Transaction accepted into pending pool: tx_id=%s hash=%.8s", tx_id, tx_hash)
        return jsonify({"status": "accepted", "transaction_id": tx_id}), 201

    except (ValueError, TypeError, BadSignatureError) as e:
        LOG.error("Signature verification failed for tx_id=%s: %s", tx_id, e)
        return jsonify({"status": "error", "message": "Signature verification failed"}), 400
    except LegacyCryptoError as e:
        LOG.error("Signature verification failed: %s", str(e))
        return jsonify({"status": "unauthorized", "message": "Signature verification failed"}), 401
    except Exception as e:
        LOG.exception("Unexpected error processing transaction: %s", e)
        return jsonify({"status": "error", "message": "Internal error"}), 500


@app.route('/mine', methods=['GET'])
def mine_block():
    """Mine a new block including pending transactions using a simple proof-of-work.

    For demo purposes, the proof is a small integer nonce where the hash of
    previous_hash + nonce has leading zeros (very small difficulty).
    """
    with chain_lock:
        if not pending_transactions:
            LOG.info("No pending transactions to mine")
            return jsonify({"status": "idle", "message": "No transactions to mine"}), 200

        last_block = chain[-1]
        previous_hash = last_block.get('hash')
        transactions_copy = list(pending_transactions)
        # Simple PoW: find nonce where sha256(previous_hash + nonce) starts with '00'
        proof = 0
        while True:
            guess = f"{previous_hash}{proof}".encode('utf-8')
            guess_hash = sha256(guess).hexdigest()
            if guess_hash.startswith('00'):
                break
            proof += 1

        block = {
            "index": last_block['index'] + 1,
            "timestamp": time.time(),
            "transactions": transactions_copy,
            "proof": proof,
            "previous_hash": previous_hash,
        }
        block_hash = _hash_block(block)
        block['hash'] = block_hash

        # Append and clear pending
        chain.append(block)
        pending_transactions.clear()

        LOG.info("Mined new block index=%s hash=%.8s tx_count=%d proof=%s", block['index'], block_hash, len(block['transactions']), proof)
        return jsonify({"status": "mined", "index": block['index'], "hash": block_hash, "tx_count": len(block['transactions'])}), 201


@app.route('/transaction/<identifier>', methods=['GET'])
def find_transaction(identifier: str):
    """Find a transaction by transaction_id (int) or transaction_hash (hex string).

    Returns the block info if found and the transaction entry with verification status.
    """
    LOG.info("Lookup request for identifier=%s from %s", identifier, request.remote_addr)
    with chain_lock:
        # Search through chain
        for block in chain:
            for tx in block.get('transactions', []):
                if str(tx.get('transaction_id')) == identifier or tx.get('transaction_hash') == identifier:
                    LOG.info("Transaction found in block index=%s tx_id=%s", block['index'], tx.get('transaction_id'))
                    return jsonify({"found": True, "block_index": block['index'], "transaction": tx}), 200
    # Not found
    LOG.warning("Transaction not found: %s", identifier)
    return jsonify({"found": False}), 404


@app.route('/chain', methods=['GET'])
def get_chain():
    with chain_lock:
        return jsonify({"length": len(chain), "chain": chain}), 200


@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy"}), 200


if __name__ == '__main__':
    LOG.info("Starting Immutable Verification Ledger on port 5003")
    app.run(host='0.0.0.0', port=5003, debug=False)
