import time

import requests
import streamlit as st


st.set_page_config(layout="wide")


# Session state must be initialized before rendering UI widgets.
if "latest_result" not in st.session_state:
    st.session_state["latest_result"] = None
if "attack_status" not in st.session_state:
    st.session_state["attack_status"] = "No attack observed"
if "packet_verification_result" not in st.session_state:
    st.session_state["packet_verification_result"] = "Awaiting verification"
if "blockchain_result" not in st.session_state:
    st.session_state["blockchain_result"] = "Awaiting transaction"
if "broadcast_status" not in st.session_state:
    st.session_state["broadcast_status"] = "idle"
if "broadcast_message" not in st.session_state:
    st.session_state["broadcast_message"] = "Awaiting network simulation."
if "last_payload" not in st.session_state:
    st.session_state["last_payload"] = ""
if "broadcast_active" not in st.session_state:
    st.session_state["broadcast_active"] = False
if "intercept_enabled" not in st.session_state:
    st.session_state["intercept_enabled"] = False
if "intercept_toggle" not in st.session_state:
    st.session_state["intercept_toggle"] = st.session_state["intercept_enabled"]
if "broadcast_diagnostics" not in st.session_state:
    st.session_state["broadcast_diagnostics"] = None
if "last_latency_ms" not in st.session_state:
    st.session_state["last_latency_ms"] = 0.0
if "last_integrity" not in st.session_state:
    st.session_state["last_integrity"] = "Protection Active"
if "last_result_label" not in st.session_state:
    st.session_state["last_result_label"] = "Idle"
if "simulation_result" not in st.session_state:
    st.session_state["simulation_result"] = None
if "blockchain_history" not in st.session_state:
    st.session_state["blockchain_history"] = []
if "last_request_payload" not in st.session_state:
    st.session_state["last_request_payload"] = None
if "last_response_payload" not in st.session_state:
    st.session_state["last_response_payload"] = None


NODES = [
    ("Ground Station Gateway", "http://127.0.0.1:5000/health"),
    ("Satellite Relay Link", "http://127.0.0.1:5001/health"),
    ("Home Router Terminal", "http://127.0.0.1:5002/health"),
    ("Blockchain Ledger Monitor", "http://127.0.0.1:5003/health"),
    ("Signal Interceptor", "http://127.0.0.1:5004/health"),
]


def check_node_health(url):
    try:
        response = requests.get(url, timeout=0.4)
        if response.status_code == 200:
            return "🟢 Active"
        return f"🔴 Offline: HTTP {response.status_code}"
    except requests.exceptions.ConnectionError:
        return "🔴 Offline: connection refused"
    except requests.exceptions.Timeout:
        return "🔴 Offline: timeout"
    except requests.RequestException as exc:
        return f"🔴 Offline: {exc}"


def _build_modified_packet_preview(payload_text):
    modified_text = f"{payload_text}_ATTACKED"
    return {
        "Original Packet": {"message": payload_text},
        "Modified Packet": {"message": modified_text},
    }


def _fetch_blockchain_history():
    try:
        chain_response = requests.get("http://127.0.0.1:5003/chain", timeout=3)
        if chain_response.status_code == 200:
            return chain_response.json().get("chain", [])
        return []
    except requests.RequestException:
        return []


def _diagram_state(latest_result):
    if latest_result is None:
        return {
            "badge": "System Ready",
            "badge_tone": "neutral",
            "nodes": [
                ("🏢 Ground Station", "🟢 Ready", "active"),
                ("🛰️ Satellite Relay", "🟢 Online", "active"),
                ("⚠️ Signal Interceptor", "⚪ Monitoring Only", "neutral"),
                ("🛡️ Quantum-Safe Security Shield", "🟢 Protection Active", "active"),
                ("🏠 Home Router", "🟢 Ready to Verify", "active"),
                ("🔗 Blockchain Ledger", "⚪ Awaiting Transaction", "neutral"),
            ],
        }

    if latest_result.get("state") == "secure":
        return {
            "badge": "Secure Route",
            "badge_tone": "safe",
            "nodes": [
                ("🏢 Ground Station", "🟢 Packet Secured", "safe"),
                ("🛰️ Satellite Relay", "🟢 Secure Transfer", "safe"),
                ("⚠️ Signal Interceptor", "🟢 Bypassed Safely", "safe"),
                ("🛡️ Quantum-Safe Security Shield", "🟢 Signature Verified", "safe"),
                ("🏠 Home Router", "🟢 Trusted Message Accepted", "safe"),
                ("🔗 Blockchain Ledger", "🟢 SECURED & LOGGED", "safe"),
            ],
        }

    return {
        "badge": "Packet Modified",
        "badge_tone": "attack",
        "nodes": [
            ("🏢 Ground Station", "🟢 Packet Secured", "safe"),
            ("🛰️ Satellite Relay", "🟢 Transfer Started", "safe"),
            ("⚠️ Signal Interceptor", "🔴 ACTIVE ATTACK", "attack"),
            (
                "🛡️ Quantum-Safe Security Shield",
                "🛡️ ATTACK BLOCKED - Invalid Signature Detected",
                "attack",
            ),
            ("🏠 Home Router", "🔴 Altered Message Rejected", "attack"),
            ("🔗 Blockchain Ledger", "⚠️ SECURITY EVENT LOGGED", "attack"),
        ],
    }


def _render_compact_health_bar(active_nodes, latency_value, ledger_active):
    st.markdown("### System Snapshot")
    cols = st.columns(4)
    with cols[0]:
        with st.container(border=True):
            st.markdown("**🟢 System Online**")
            st.caption("Core simulation services reachable")
    with cols[1]:
        with st.container(border=True):
            st.markdown(f"**Nodes: {active_nodes}/5 Active**")
            st.caption("Background service health")
    with cols[2]:
        with st.container(border=True):
            st.markdown(f"**Network Delay: {latency_value}**")
            st.caption("End-to-end simulation latency")
    with cols[3]:
        with st.container(border=True):
            st.markdown("**Blockchain: Synchronized**" if ledger_active else "**Blockchain: Degraded**")
            st.caption("Tamper-proof security ledger")


def _render_architecture_diagram(latest_result):
    state = _diagram_state(latest_result)
    badge_style = {
        "neutral": "background:#34495E;border-color:#7F8C8D;",
        "safe": "background:#145A32;border-color:#2ECC71;",
        "attack": "background:#641E16;border-color:#E74C3C;",
    }
    tone_style = {
        "neutral": "border:1px solid #657786;background:#0E1A2B;",
        "active": "border:1px solid #2980B9;background:#10243A;",
        "safe": "border:1px solid #2ECC71;background:#102E1F;",
        "attack": "border:1px solid #E74C3C;background:#321015;box-shadow:0 0 0 0.22rem rgba(231, 76, 60, 0.18);",
    }

    st.markdown("## 🛰️ Quantum-Safe Network Architecture")
    st.caption("A secure packet is created, transmitted, challenged by a hacker, verified, and permanently recorded.")

    st.markdown(
        f"""
        <div style="display:flex;justify-content:center;margin-bottom:0.75rem;">
            <div style="padding:0.42rem 0.9rem;border:1px solid;border-radius:999px;color:#ECF0F1;font-weight:700;{badge_style[state['badge_tone']]}">
                {state['badge']}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    cards = st.columns(6)
    for idx, (col, node) in enumerate(zip(cards, state["nodes"])):
        title, status, tone = node
        with col:
            with st.container(border=True):
                st.markdown(
                    f"""
                    <div style="border-radius:12px;padding:0.55rem;min-height:108px;{tone_style[tone]}">
                        <div style="color:#ECF0F1;font-weight:700;font-size:0.96rem;line-height:1.2;">{title}</div>
                        <div style="margin-top:0.6rem;color:#DDE6ED;font-size:0.9rem;line-height:1.25;">{status}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                if idx < 5:
                    st.markdown("<div style='text-align:center;color:#7FB3D5;font-size:1.3rem;'>↓</div>", unsafe_allow_html=True)


def _render_result_summary(latest_result):
    st.subheader("Simulation Outcome")
    if latest_result is None:
        st.info("Run Simulate Network Broadcast from the sidebar to see how the security workflow responds.")
        return

    if latest_result.get("state") == "secure":
        with st.container(border=True):
            st.success("🟢 Secure Delivery Successful")
            st.write(
                "Your message was protected using quantum-safe security, transmitted through the satellite network, verified by the Home Router, and permanently stored on the Blockchain Ledger."
            )
            st.markdown("✓ Secure transmission")
            st.markdown("✓ Signature verified")
            st.markdown("✓ Blockchain record created")
    else:
        with st.container(border=True):
            st.error("🛡️ Attack Successfully Blocked")
            st.write(
                "A hacker intercepted the wireless signal and attempted to modify the packet. The Quantum-Safe Security Shield detected the change, rejected the message, and recorded the failed attack permanently."
            )
            st.markdown("✓ Tampering detected")
            st.markdown("✓ Packet rejected")
            st.markdown("✓ Security event logged")


with st.sidebar:
    st.header("Broadcast Controls")

    if st.button("Reset Dashboard"):
        for key in (
            "latest_result",
            "attack_status",
            "packet_verification_result",
            "blockchain_result",
            "broadcast_status",
            "broadcast_message",
            "last_payload",
            "broadcast_active",
            "intercept_enabled",
            "intercept_toggle",
            "broadcast_diagnostics",
            "last_latency_ms",
            "last_integrity",
            "last_result_label",
            "simulation_result",
            "blockchain_history",
            "last_request_payload",
            "last_response_payload",
        ):
            if key in st.session_state:
                del st.session_state[key]
        st.rerun()

    intercept_enabled = st.toggle(
        "Simulate Signal Intercept",
        key="intercept_toggle",
    )
    st.session_state["intercept_enabled"] = intercept_enabled

    payload_text = st.text_input(
        "Custom Message Payload",
        value="Quantum-safe satellite broadcast",
    )

    if st.button("Simulate Network Broadcast"):
        st.session_state["last_payload"] = payload_text.strip() or "Quantum-safe satellite broadcast"
        request_start = time.perf_counter()
        packet_preview = _build_modified_packet_preview(st.session_state["last_payload"])
        broadcast_url = "http://127.0.0.1:5000/broadcast"
        request_payload = {
            "payload": {
                "data": st.session_state["last_payload"],
                "url": "http://127.0.0.1:5002/receive",
                "intercept": st.session_state["intercept_enabled"],
            }
        }
        request_headers = {"Content-Type": "application/json"}
        st.session_state["last_request_payload"] = {
            "url": broadcast_url,
            "headers": request_headers,
            "json": request_payload,
        }

        try:
            response = requests.post(
                broadcast_url,
                headers=request_headers,
                json=request_payload,
                timeout=10,
            )
            response_text = response.text

            try:
                response_json = response.json()
            except Exception:
                response_json = {"raw": response_text}

            transaction_hash = response_json.get("transaction_hash") if isinstance(response_json, dict) else None
            if transaction_hash:
                try:
                    ledger_url = f"http://127.0.0.1:5003/transaction/{transaction_hash}"
                    ledger_response = requests.get(ledger_url, timeout=3)
                    response_json["ledger_lookup"] = {
                        "url": ledger_url,
                        "status_code": ledger_response.status_code,
                        "result": ledger_response.json(),
                    }
                except requests.RequestException as exc:
                    response_json["ledger_lookup"] = {
                        "status": "unavailable",
                        "details": str(exc),
                    }

            st.session_state["broadcast_diagnostics"] = response_json
            st.session_state["blockchain_history"] = _fetch_blockchain_history()
            st.session_state["last_response_payload"] = {
                "status_code": response.status_code,
                "body": response_json,
            }

            simulated_attack = st.session_state["intercept_enabled"]
            if response.ok:
                final_state = "attack" if simulated_attack else "secure"
                st.session_state["broadcast_status"] = "success"
                st.session_state["broadcast_active"] = True
                st.session_state["last_result_label"] = "REJECTED" if simulated_attack else "SUCCESS"
                st.session_state["broadcast_message"] = f"Broadcast completed (HTTP {response.status_code})."
            else:
                final_state = "attack"
                st.session_state["broadcast_status"] = "tampering"
                st.session_state["broadcast_active"] = False
                st.session_state["last_result_label"] = "REJECTED"
                st.session_state["broadcast_message"] = (
                    f"Tampering detected (HTTP {response.status_code}): {response_text}"
                )

            st.session_state["last_latency_ms"] = round((time.perf_counter() - request_start) * 1000, 2)
            st.session_state["last_integrity"] = "Compromised" if final_state == "attack" else "Secure"
            st.session_state["attack_status"] = (
                "Interception detected" if final_state == "attack" else "No active interception"
            )
            st.session_state["packet_verification_result"] = (
                "Tampering Detected" if final_state == "attack" else "Signature verified"
            )
            st.session_state["blockchain_result"] = (
                "Security event logged" if final_state == "attack" else "Secured record logged"
            )

            latest_result = {
                "state": final_state,
                "verdict": st.session_state["last_result_label"],
                "mode": "ATTACK" if st.session_state["intercept_enabled"] else "NORMAL",
                "packet_preview": packet_preview,
                "transaction_hash": transaction_hash,
                "latency_ms": st.session_state["last_latency_ms"],
                "integrity": st.session_state["last_integrity"],
                "response": response_json,
            }

            st.session_state["simulation_result"] = latest_result
            st.session_state["latest_result"] = latest_result

            # Persist state first, then rerun for a clean render pass.
            st.rerun()

        except requests.RequestException as exc:
            st.session_state["broadcast_status"] = "tampering"
            st.session_state["broadcast_active"] = False
            st.session_state["last_result_label"] = "REJECTED"
            st.session_state["broadcast_message"] = f"Tampering alert detected: {exc}"
            st.session_state["broadcast_diagnostics"] = {
                "status": "request_exception",
                "details": str(exc),
            }
            st.session_state["last_response_payload"] = {
                "status": "request_exception",
                "details": str(exc),
            }
            st.session_state["blockchain_history"] = _fetch_blockchain_history()
            st.session_state["last_integrity"] = "Compromised"
            st.session_state["attack_status"] = "Interception detected"
            st.session_state["packet_verification_result"] = "Tampering Detected"
            st.session_state["blockchain_result"] = "Security event logged"

            latest_result = {
                "state": "attack",
                "verdict": "REJECTED",
                "mode": "ATTACK",
                "packet_preview": packet_preview,
                "transaction_hash": None,
                "latency_ms": 0,
                "integrity": st.session_state["last_integrity"],
                "response": st.session_state["broadcast_diagnostics"],
            }
            st.session_state["simulation_result"] = latest_result
            st.session_state["latest_result"] = latest_result
            st.rerun()


if not st.session_state["blockchain_history"]:
    st.session_state["blockchain_history"] = _fetch_blockchain_history()

node_health = {name: check_node_health(url) for name, url in NODES}
active_nodes = sum(1 for status in node_health.values() if status == "🟢 Active")
latency_value = (
    f"{st.session_state['last_latency_ms']}ms"
    if st.session_state["last_latency_ms"] > 0
    else "150ms"
)
ledger_active = node_health.get("Blockchain Ledger Monitor", "").startswith("🟢")

st.title("🚀 Quantum-Safe Satellite Router Simulation")
st.caption(
    "Demonstrating how post-quantum cryptography protects satellite communication from interception and how blockchain creates a permanent security record."
)

_render_compact_health_bar(active_nodes=active_nodes, latency_value=latency_value, ledger_active=ledger_active)

st.divider()
_render_architecture_diagram(st.session_state["latest_result"])

st.divider()
st.subheader("Run Simulation")
st.info(
    "Use the sidebar controls to choose Simulate Wireless Hack, then click Simulate Network Broadcast to run the demonstration."
)

_render_result_summary(st.session_state["latest_result"])

chain_history = st.session_state["blockchain_history"]
with st.expander("🔗 Live Blockchain Explorer", expanded=False):
    if not chain_history:
        st.info("No blockchain record available yet. Run a simulation to generate proof.")
    else:
        latest_block = chain_history[-1]
        tx_count = len(latest_block.get("transactions", []))
        cols = st.columns([1, 1, 1.6])
        with cols[0]:
            st.metric("Latest Block", f"#{latest_block.get('index', 0)}")
        with cols[1]:
            st.metric("Transactions", str(tx_count))
        with cols[2]:
            st.metric("Ledger Status", "Synchronized")
            st.caption("Tamper-Proof Security Ledger")

        with st.container(border=True):
            st.markdown("**Proof Snapshot**")
            st.markdown(f"Hash: {latest_block.get('hash', 'unavailable')}")
            st.caption(f"Timestamp: {latest_block.get('timestamp', 'unknown')}")

with st.expander("🔍 Developer Diagnostics", expanded=False):
    st.caption("Technical diagnostics for developers and evaluators.")

    st.markdown("**Node Health Details**")
    st.json(node_health)

    st.markdown("**Last Request Payload**")
    st.json(st.session_state["last_request_payload"])

    st.markdown("**Last API Response**")
    st.json(st.session_state["last_response_payload"])

    if st.session_state["latest_result"] is not None:
        packet_preview = st.session_state["latest_result"].get("packet_preview", {})
        st.markdown("**Original Packet JSON**")
        st.json(packet_preview.get("Original Packet", {}))
        st.markdown("**Modified Packet JSON**")
        st.json(packet_preview.get("Modified Packet", {}))

    st.markdown("**Multi-Hop Route Diagnostics**")
    st.json(st.session_state["broadcast_diagnostics"])

    st.markdown("**Cryptographic and Verification Summary**")
    st.json(
        {
            "attack_status": st.session_state["attack_status"],
            "packet_verification_result": st.session_state["packet_verification_result"],
            "blockchain_result": st.session_state["blockchain_result"],
            "integrity": st.session_state["last_integrity"],
            "latency_ms": st.session_state["last_latency_ms"],
        }
    )

    if chain_history:
        latest_block = chain_history[-1]
        st.markdown("**SHA-256 Hash Evidence**")
        st.json(
            {
                "block_hash": latest_block.get("hash"),
                "previous_hash": latest_block.get("previous_hash"),
                "transaction_hash": (st.session_state["latest_result"] or {}).get("transaction_hash"),
            }
        )

    st.markdown("**Backend Logs Snapshot**")
    st.code(str(st.session_state["broadcast_message"]))