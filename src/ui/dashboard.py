import streamlit as st
import requests


st.set_page_config(layout="wide")


def check_node_health(url):
    try:
        response = requests.get(url, timeout=0.3)
        if response.status_code == 200:
            return "🟢 Active"
        return "🚨 Node Offline"
    except requests.exceptions.ConnectionError:
        # This catches the exact exception when a port is completely dead
        return "🚨 Node Offline"

st.markdown(
    "<h1 style='text-align: center; color: #2C7BE5;'>Project Genesis: Quantum-Safe Satellite Router Terminal</h1>",
    unsafe_allow_html=True,
)

if "broadcast_status" not in st.session_state:
    st.session_state.broadcast_status = "idle"
    st.session_state.broadcast_message = "Awaiting network simulation."
    st.session_state.last_payload = ""
    st.session_state.broadcast_active = False

with st.sidebar:
    st.header("Broadcast Controls")
    payload_text = st.text_input(
        "Custom Message Payload",
        value="Quantum-safe satellite broadcast",
    )
    if st.button("Simulate Network Broadcast"):
        st.session_state.last_payload = payload_text.strip() or "Quantum-safe satellite broadcast"
        broadcast_url = "http://127.0.0.1:5000/broadcast"
        request_payload = {
            "payload": {
                "data": st.session_state.last_payload,
                "url": "http://127.0.0.1:5002/receive",
            }
        }
        request_headers = {"Content-Type": "application/json"}

        # Temporary diagnostics to trace outgoing request shape.
        print(f"[DASHBOARD] Outgoing URL: {broadcast_url}")
        print("[DASHBOARD] Outgoing method: POST")
        print(f"[DASHBOARD] Outgoing headers: {request_headers}")
        print(f"[DASHBOARD] Outgoing JSON payload: {request_payload}")

        st.caption(f"Outgoing URL: {broadcast_url}")
        st.caption("Outgoing method: POST")
        st.json({
            "headers": request_headers,
            "json": request_payload,
        })

        try:
            response = requests.post(
                broadcast_url,
                headers=request_headers,
                json=request_payload,
                timeout=10,
            )
            response_text = response.text
            print(f"[DASHBOARD] Response status: {response.status_code}")
            print(f"[DASHBOARD] Response body: {response_text}")
            if response.ok:
                st.session_state.broadcast_status = "success"
                st.session_state.broadcast_active = True
                st.session_state.broadcast_message = (
                    f"Broadcast delivered successfully (HTTP {response.status_code})."
                )
            else:
                st.session_state.broadcast_status = "tampering"
                st.session_state.broadcast_active = False
                st.session_state.broadcast_message = (
                    f"Tampering alert detected (HTTP {response.status_code}): {response_text}"
                )
        except requests.RequestException as exc:
            st.session_state.broadcast_status = "tampering"
            st.session_state.broadcast_active = False
            st.session_state.broadcast_message = f"Tampering alert detected: {exc}"

    st.caption(f"Last payload: {st.session_state.last_payload or 'None'}")
    st.info(st.session_state.broadcast_message)

nodes = [
    ("Ground Station Gateway", "Port 5000", "http://localhost:5000/health"),
    ("Satellite Relay Link", "Port 5001", "http://localhost:5001/health"),
    ("Blockchain Ledger Monitor", "Port 5003", "http://localhost:5003/health"),
    ("Home Router Terminal", "Port 5002", "http://localhost:5002/health"),
]

node_health = {title: check_node_health(url) for title, _, url in nodes}

row1_cols = st.columns(2)
for col, (title, port, url) in zip(row1_cols, nodes[:2]):
    with col:
        st.markdown(f"### {title}")
        st.caption(port)
        st.write("Core relay node in the quantum-safe network simulation.")
        if node_health[title]:
            if title == "Ground Station Gateway":
                st.success("🟢 Ground Station Operational")
            else:
                st.success(f"🟢 {title} Operational")
        else:
            st.error("🚨 Node Offline")

row2_cols = st.columns(2)
for col, (title, port, url) in zip(row2_cols, nodes[2:]):
    with col:
        st.markdown(f"### {title}")
        st.caption(port)
        st.write("Core relay node in the quantum-safe network simulation.")
        if node_health[title]:
            st.success(f"🟢 {title} Operational")
        else:
            st.error("🚨 Node Offline")
