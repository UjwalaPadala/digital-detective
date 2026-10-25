
import streamlit as st
import pandas as pd
import plotly.express as px
import psycopg2

st.set_page_config(
    page_title="Digital Detective",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Digital Detective")
st.caption("Cybersecurity Log Intelligence & Threat Detection")

# Sidebar
st.sidebar.header("Dashboard Controls")
st.sidebar.caption("Connect to your local PostgreSQL database.")

password = st.sidebar.text_input(
    "PostgreSQL password",
    type="password"
)

refresh = st.sidebar.button(
    "🔄 Refresh Security Data",
    type="primary",
    use_container_width=True
)

st.sidebar.divider()
st.sidebar.info("Data source: PostgreSQL · digital_detective")

if refresh:
    if not password:
        st.error("Enter your PostgreSQL password in the sidebar.")
        st.stop()

    try:
        conn = psycopg2.connect(
            host="127.0.0.1",
            port=5432,
            database="digital_detective",
            user="postgres",
            password=password
        )

        logs = pd.read_sql_query(
            """
            SELECT event_id, event_time, user_id, event_type,
                   ip_address, country, resource_accessed,
                   data_volume_mb, status
            FROM raw_security_logs
            ORDER BY event_time DESC
            """,
            conn
        )

        alerts = pd.read_sql_query(
            "SELECT * FROM incident_alerts",
            conn
        )

        conn.close()

        # Cache this refresh result for the current session
        st.session_state["logs"] = logs
        st.session_state["alerts"] = alerts

    except Exception as error:
        st.error(f"Database error: {error}")
        st.stop()

if "logs" not in st.session_state:
    st.info(
        "Enter your PostgreSQL password in the sidebar, "
        "then click Refresh Security Data."
    )
    st.stop()

logs = st.session_state["logs"].copy()
alerts = st.session_state["alerts"].copy()

if logs.empty:
    st.warning("No security logs found in the database.")
    st.stop()

# Clean data for analysis
logs["event_time"] = pd.to_datetime(
    logs["event_time"], errors="coerce"
)
logs["data_volume_mb"] = pd.to_numeric(
    logs["data_volume_mb"], errors="coerce"
).fillna(0)

logs["status"] = logs["status"].fillna("Unknown").astype(str)
logs["event_type"] = logs["event_type"].fillna("Unknown").astype(str)

# Sidebar filters
st.sidebar.subheader("Filters")

users = sorted(logs["user_id"].dropna().unique().tolist())
selected_users = st.sidebar.multiselect(
    "Select users",
    users,
    default=users
)

event_types = sorted(logs["event_type"].unique().tolist())
selected_events = st.sidebar.multiselect(
    "Event types",
    event_types,
    default=event_types
)

statuses = sorted(logs["status"].unique().tolist())
selected_statuses = st.sidebar.multiselect(
    "Statuses",
    statuses,
    default=statuses
)

filtered = logs[
    logs["user_id"].isin(selected_users)
    & logs["event_type"].isin(selected_events)
    & logs["status"].isin(selected_statuses)
].copy()

# Identify suspicious behavior
status_text = filtered["status"].str.lower()
event_text = filtered["event_type"].str.lower()

failed_mask = (
    status_text.str.contains("fail|denied|blocked", regex=True)
    | event_text.str.contains("fail|denied", regex=True)
)

failed = filtered[failed_mask]

large_access = filtered[
    filtered["data_volume_mb"] >= 500
]

failed_counts = failed.groupby("user_id").size()
large_counts = large_access.groupby("user_id").size()
volume_by_user = filtered.groupby("user_id")[
    "data_volume_mb"
].sum()

threats = pd.DataFrame(index=sorted(filtered["user_id"].unique()))
threats.index.name = "User ID"
threats["Failed Logins"] = failed_counts
threats["Large Access Events"] = large_counts
threats["Total Data (MB)"] = volume_by_user
threats = threats.fillna(0)

threats["Risk"] = threats.apply(
    lambda row: (
        "HIGH PRIORITY"
        if row["Failed Logins"] >= 3
        or row["Large Access Events"] >= 2
        else "REVIEW"
        if row["Failed Logins"] > 0
        or row["Large Access Events"] > 0
        else "NORMAL"
    ),
    axis=1
)

# Summary metrics
st.subheader("Security Overview")

c1, c2, c3, c4 = st.columns(4)
c1.metric("Events", len(filtered))
c2.metric("Unique Users", filtered["user_id"].nunique())
c3.metric("Failed Events", len(failed))
c4.metric("Incident Alerts", len(alerts))

# Threat panel
st.subheader("🚨 High-Priority Threats")

high = threats[threats["Risk"] == "HIGH PRIORITY"].reset_index()

if high.empty:
    st.success("No users currently meet the high-priority rules.")
else:
    st.warning(
        f"{len(high)} user(s) meet the high-priority detection rules."
    )
    st.dataframe(high, use_container_width=True, hide_index=True)

with st.expander("View all user risk summaries"):
    st.dataframe(
        threats.reset_index(),
        use_container_width=True,
        hide_index=True
    )

# Charts
left, right = st.columns(2)

with left:
    st.subheader("Events by Type")
    event_counts = (
        filtered["event_type"]
        .value_counts()
        .rename_axis("Event Type")
        .reset_index(name="Count")
    )
    fig = px.bar(
        event_counts,
        x="Event Type",
        y="Count",
        color="Event Type",
        title="Security event distribution"
    )
    st.plotly_chart(fig, use_container_width=True)

with right:
    st.subheader("Data Access by User")
    volume = (
        filtered.groupby("user_id", as_index=False)["data_volume_mb"]
        .sum()
        .sort_values("data_volume_mb", ascending=False)
    )
    fig = px.bar(
        volume,
        x="user_id",
        y="data_volume_mb",
        labels={
            "user_id": "User",
            "data_volume_mb": "Data Volume (MB)"
        },
        title="Total data volume accessed"
    )
    st.plotly_chart(fig, use_container_width=True)

st.subheader("📈 Activity Over Time")

timeline = filtered.dropna(subset=["event_time"]).copy()

if not timeline.empty:
    timeline["Time"] = timeline["event_time"].dt.floor("min")
    timeline_counts = (
        timeline.groupby("Time")
        .size()
        .reset_index(name="Events")
    )
    fig = px.line(
        timeline_counts,
        x="Time",
        y="Events",
        markers=True,
        title="Security events over time"
    )
    st.plotly_chart(fig, use_container_width=True)
else:
    st.info("No valid event timestamps available for the timeline.")

# Tables
st.subheader("🔍 Security Logs")
st.dataframe(
    filtered.sort_values("event_time", ascending=False),
    use_container_width=True,
    hide_index=True
)

st.subheader("📋 Database Incident Alerts")
if alerts.empty:
    st.info("There are currently no records in incident_alerts.")
else:
    st.dataframe(alerts, use_container_width=True, hide_index=True)

st.caption(
    "Risk labels are based on simple demonstration rules. "
    "They are indicators for investigation, not proof of malicious activity."
)
