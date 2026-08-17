import streamlit as st
import sqlite3
import pandas as pd
from pathlib import Path
from streamlit_autorefresh import st_autorefresh


# ============================================================
# CONFIGURATION
# ============================================================

DATABASE = Path(__file__).parent.parent / "data" / "security_events.db"

st.set_page_config(
    page_title="Real-Time Security Monitor",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# AUTO REFRESH
# ============================================================

# Refresh dashboard every 5 seconds
st_autorefresh(
    interval=5000,
    key="security_monitor_refresh"
)


# ============================================================
# DATABASE FUNCTION
# ============================================================

def load_events():

    if not DATABASE.exists():
        return pd.DataFrame()

    connection = sqlite3.connect(DATABASE)

    query = """
        SELECT
            id,
            timestamp,
            threat_type,
            source_ip,
            destination_ip,
            port,
            severity,
            message
        FROM security_events
        ORDER BY id DESC
    """

    dataframe = pd.read_sql_query(
        query,
        connection
    )

    connection.close()

    return dataframe


# ============================================================
# LOAD DATA
# ============================================================

df = load_events()


# ============================================================
# HEADER
# ============================================================

st.title("🛡️ Real-Time Security Monitoring & IDS")

st.caption(
    "Live network threat detection and security event monitoring"
)

st.markdown(
    "**Status:** 🟢 Monitoring Active"
)


# ============================================================
# CALCULATE METRICS
# ============================================================

if not df.empty:

    total_alerts = len(df)

    high_alerts = len(
        df[df["severity"] == "HIGH"]
    )

    medium_alerts = len(
        df[df["severity"] == "MEDIUM"]
    )

    low_alerts = len(
        df[df["severity"] == "LOW"]
    )

    port_scan_alerts = len(
        df[df["threat_type"] == "Port Scan"]
    )

    excessive_connection_alerts = len(
        df[df["threat_type"] == "Excessive Connections"]
    )

else:

    total_alerts = 0
    high_alerts = 0
    medium_alerts = 0
    low_alerts = 0
    port_scan_alerts = 0
    excessive_connection_alerts = 0


# ============================================================
# METRICS
# ============================================================

col1, col2, col3, col4 = st.columns(4)

with col1:

    st.metric(
        "Total Alerts",
        total_alerts
    )


with col2:

    st.metric(
        "High Severity",
        high_alerts
    )


with col3:

    st.metric(
        "Medium Severity",
        medium_alerts
    )


with col4:

    st.metric(
        "Port Scan Alerts",
        port_scan_alerts
    )


st.divider()


# ============================================================
# THREAT SUMMARY
# ============================================================

st.subheader("📊 Threat Summary")


if not df.empty:

    threat_counts = (
        df["threat_type"]
        .value_counts()
        .reset_index()
    )

    threat_counts.columns = [
        "Threat Type",
        "Count"
    ]

    st.bar_chart(
        threat_counts.set_index("Threat Type")
    )

else:

    st.info(
        "No security threats detected yet."
    )


st.divider()


# ============================================================
# SEVERITY SUMMARY
# ============================================================

st.subheader("🚨 Severity Summary")


severity_data = pd.DataFrame(
    {
        "Severity": [
            "HIGH",
            "MEDIUM",
            "LOW"
        ],
        "Count": [
            high_alerts,
            medium_alerts,
            low_alerts
        ]
    }
)

st.bar_chart(
    severity_data.set_index("Severity")
)


st.divider()


# ============================================================
# SOURCE IP SUMMARY
# ============================================================

st.subheader("🌐 Top Source IPs")


if not df.empty:

    source_counts = (
        df["source_ip"]
        .value_counts()
        .head(10)
        .reset_index()
    )

    source_counts.columns = [
        "Source IP",
        "Alerts"
    ]

    st.dataframe(
        source_counts,
        use_container_width=True,
        hide_index=True
    )

else:

    st.info(
        "No source IP data available."
    )


st.divider()


# ============================================================
# RECENT SECURITY ALERTS
# ============================================================

st.subheader("🔔 Recent Security Alerts")


if not df.empty:

    display_columns = [
        "timestamp",
        "threat_type",
        "source_ip",
        "destination_ip",
        "port",
        "severity",
        "message"
    ]

    st.dataframe(
        df[display_columns].head(20),
        use_container_width=True,
        hide_index=True
    )

else:

    st.info(
        "No security alerts available."
    )


st.divider()


# ============================================================
# STATISTICS
# ============================================================

st.subheader("📈 Detection Statistics")


col1, col2 = st.columns(2)


with col1:

    st.write(
        f"**Port Scan Alerts:** {port_scan_alerts}"
    )

    st.write(
        f"**Excessive Connection Alerts:** "
        f"{excessive_connection_alerts}"
    )


with col2:

    st.write(
        f"**High Severity:** {high_alerts}"
    )

    st.write(
        f"**Medium Severity:** {medium_alerts}"
    )


st.divider()


# ============================================================
# FOOTER
# ============================================================

st.caption(
    "Data source: SQLite security_events.db"
)

st.caption(
    "Dashboard automatically refreshes every 5 seconds."
)