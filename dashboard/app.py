"""Streamlit dashboard over the ShipGuard audit DB (read-only).

    SHIPGUARD_AUDIT_DB=sqlite:///./data/audit.db streamlit run dashboard/app.py
"""

from __future__ import annotations

import json
import os
from collections import Counter

import pandas as pd
import sqlalchemy as sa
import streamlit as st

DB = os.environ.get("SHIPGUARD_AUDIT_DB", "sqlite:///./data/audit.db")

st.set_page_config(page_title="ShipGuard audit", layout="wide")
st.title("ShipGuard audit trail")
st.caption(f"Source: `{DB}` (hashed / redacted metadata only)")


@st.cache_data(ttl=5)
def load(limit: int) -> pd.DataFrame:
    engine = sa.create_engine(DB)
    try:
        return pd.read_sql(f"SELECT * FROM auditevent ORDER BY id DESC LIMIT {int(limit)}", engine)
    except Exception:
        return pd.DataFrame()


limit = st.sidebar.slider("Rows", 50, 5000, 500, step=50)
df = load(limit)
if df.empty:
    st.info("No audit events yet. Send a request through the gateway (`make demo`).")
    st.stop()

decisions = st.sidebar.multiselect("Decision", sorted(df.decision.unique()), default=sorted(df.decision.unique()))
df = df[df.decision.isin(decisions)]

c1, c2, c3, c4 = st.columns(4)
c1.metric("Requests", len(df))
c2.metric("Blocked", f"{(df.decision == 'block').mean():.0%}")
c3.metric("Modified", f"{(df.decision == 'modify').mean():.0%}")
overhead = (df.latency_ms - df.upstream_latency_ms).clip(lower=0)
c4.metric("Gateway overhead p95", f"{overhead.quantile(0.95):.1f} ms")

left, right = st.columns(2)
with left:
    st.subheader("Decisions")
    st.bar_chart(df.decision.value_counts())
with right:
    st.subheader("Filters fired")
    counts = Counter(f for row in df.filters_fired for f in json.loads(row or "[]"))
    st.bar_chart(pd.Series(counts, dtype="int64").sort_values(ascending=False))

st.subheader("Finding kinds")
kinds = Counter(f["kind"] for row in df.findings for f in json.loads(row or "[]"))
st.dataframe(pd.DataFrame(kinds.most_common(), columns=["kind", "count"]), use_container_width=True)

st.subheader("Recent events")
st.dataframe(df[["ts", "request_id", "decision", "reason", "filters_fired", "model", "upstream", "redactions",
                 "latency_ms", "redacted_preview"]], use_container_width=True)
