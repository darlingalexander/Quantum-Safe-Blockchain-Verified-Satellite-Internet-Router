import streamlit as st
import requests


st.set_page_config(layout="wide")

st.markdown(
    "<h1 style='text-align: center; color: #2C7BE5;'>Project Genesis: Quantum-Safe Satellite Router Terminal</h1>",
    unsafe_allow_html=True,
)

if "broadcast_status" not in st.session_state:
    st.session_state.broadcast_status = "idle"
    st.session_state.broadcast_message = "Awaiting network simulation."
    st.session_state.last_payload = ""

with st.sidebar:
    st.header("Broadcast Controls")
    payload_text = st.text_input(
        "Custom Message Payload",
        value="Quantum-safe satellite broadcast",
    )
    if st.button("Simulate Network Broadcast"):
        st.session_state.last_payload = payload_text.strip() or "Quantum-safe satellite broadcast"
        try:
            response = requests.post(
                "http://localhost:5000/payload",
                json={
                    "data": st.session_state.last_payload,
                    "url": "http://localhost:5002",
                },
                timeout=10,
            )
            if response.ok:
                st.session_state.broadcast_status = "success"
                st.session_state.broadcast_message = (
                    f"Broadcast delivered successfully (HTTP {response.status_code})."
                )
            else:
                st.session_state.broadcast_status = "tampering"
                st.session_state.broadcast_message = (
                    f"Tampering alert detected (HTTP {response.status_code})."
                )
        except requests.RequestException as exc:
            st.session_state.broadcast_status = "tampering"
            st.session_state.broadcast_message = f"Tampering alert detected: {exc}"

    st.caption(f"Last payload: {st.session_state.last_payload or 'None'}")
    st.info(st.session_state.broadcast_message)

nodes = [
    ("Ground Station Gateway", "Port 5000"),
    ("Satellite Relay Link", "Port 5001"),
    ("Blockchain Ledger Monitor", "Port 5003"),
    ("Home Router Terminal", "Port 5002"),
]

row1_cols = st.columns(2)
for col, (title, port) in zip(row1_cols, nodes[:2]):
    with col:
        st.markdown(f"### {title}")
        st.caption(port)
        st.write("Core relay node in the quantum-safe network simulation.")
        if st.session_state.broadcast_status == "success":
            st.success("✅ Broadcast propagated successfully")
        elif st.session_state.broadcast_status == "tampering":
            st.error("🚨 Tampering alert observed")
        else:
            st.info("⏳ Awaiting network simulation")

row2_cols = st.columns(2)
for col, (title, port) in zip(row2_cols, nodes[2:]):
    with col:
        st.markdown(f"### {title}")
        st.caption(port)
        st.write("Core relay node in the quantum-safe network simulation.")
        if st.session_state.broadcast_status == "success":
            st.success("✅ Broadcast propagated successfully")
        elif st.session_state.broadcast_status == "tampering":
            st.error("🚨 Tampering alert observed")
        else:
            st.info("⏳ Awaiting network simulation")
