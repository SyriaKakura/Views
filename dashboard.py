"""Simple Streamlit dashboard for prediction log overview."""

from __future__ import annotations

import os
import sqlite3

import pandas as pd
import streamlit as st

DB_PATH = os.getenv("DB_PATH", "artifacts/predictions.db")

st.set_page_config(page_title="Malicious URL Detector Dashboard", layout="wide")
st.title("恶意 URL 检测仪表盘")

if not os.path.exists(DB_PATH):
    st.warning(f"数据库不存在：{DB_PATH}")
    st.stop()

query = "SELECT ts, url, score, malicious, model_version, latency_ms FROM predictions ORDER BY id DESC LIMIT 5000"
df = pd.read_sql_query(query, sqlite3.connect(DB_PATH))

if df.empty:
    st.info("暂无预测数据")
    st.stop()

df["ts"] = pd.to_datetime(df["ts"])

col1, col2, col3 = st.columns(3)
col1.metric("总样本数", len(df))
col2.metric("恶意判定占比", f"{(df['malicious'].mean() * 100):.2f}%")
col3.metric("平均延迟(ms)", f"{df['latency_ms'].mean():.2f}")

st.subheader("延迟趋势")
st.line_chart(df.sort_values("ts").set_index("ts")["latency_ms"])

st.subheader("最近预测样本")
st.dataframe(df.head(200), use_container_width=True)
