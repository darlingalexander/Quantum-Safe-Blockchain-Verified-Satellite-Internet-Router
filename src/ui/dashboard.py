import streamlit as st
import requests


st.set_page_config(layout="wide")


def check_node_health(url: str) -> bool:
    """Return True when the local node responds as active, even if it returns 404."""
    try:
        response = requests.get(url, timeout=0.2)
        return response.status_code in {200, 404}
    except requests.RequestException:
        return False

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
        try:
            response = requests.post(
                broadcast_url,
                json={
                    "payload": {
                        "data": st.session_state.last_payload,
                        "url": "http://127.0.0.1:5002",
                    }
                },
                timeout=10,
            )
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
                    f"Tampering alert detected (HTTP {response.status_code})."
                )
        except requests.RequestException as exc:
            st.session_state.broadcast_status = "tampering"
            st.session_state.broadcast_active = False
            st.session_state.broadcast_message = f"Tampering alert detected: {exc}"

    st.caption(f"Last payload: {st.session_state.last_payload or 'None'}")
    st.info(st.session_state.broadcast_message)

nodes = [
    ("Ground Station Gateway", "Port 5000", "http://localhost:5000"),
    ("Satellite Relay Link", "Port 5001", "http://localhost:5001"),
    ("Blockchain Ledger Monitor", "Port 5003", "http://localhost:5003"),
    ("Home Router Terminal", "Port 5002", "http://localhost:5002"),
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
