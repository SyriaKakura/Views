"""Streamlit dashboard for online logs + offline systematic experiment report."""

from __future__ import annotations

import json
import os
import sqlite3
import time

import joblib
import pandas as pd
import streamlit as st

from app.storage import init_db, insert_prediction

DB_PATH = os.getenv("DB_PATH", "artifacts/predictions.db")
EXPERIMENT_PATH = os.getenv("EXPERIMENT_PATH", "artifacts/experiment_report.json")
MODEL_PATH = os.getenv("MODEL_PATH", "artifacts/url_detector.joblib")
MODEL_VERSION = os.getenv("MODEL_VERSION", "dashboard-local")

st.set_page_config(page_title="Malicious URL Detector Dashboard", layout="wide")
st.title("恶意 URL 检测闭环仪表盘")


@st.cache_resource
def load_model_bundle():
    if not os.path.exists(MODEL_PATH):
        return None
    obj = joblib.load(MODEL_PATH)
    if isinstance(obj, dict) and "pipeline" in obj:
        return obj
    return {"pipeline": obj, "meta": {"threshold": 0.5}}


def local_detect(urls: list[str]) -> tuple[pd.DataFrame, float, float]:
    bundle = load_model_bundle()
    if bundle is None:
        raise FileNotFoundError(f"模型文件不存在: {MODEL_PATH}")

    model = bundle["pipeline"]
    threshold = float(bundle.get("meta", {}).get("threshold", 0.5))

    t0 = time.time()
    probs = model.predict_proba(urls)[:, 1].tolist()
    latency_ms = (time.time() - t0) * 1000.0

    init_db(DB_PATH)
    avg_latency = latency_ms / max(len(urls), 1)
    rows = []
    for url, prob in zip(urls, probs):
        malicious = float(prob) >= threshold
        insert_prediction(
            DB_PATH,
            url=url,
            score=float(prob),
            malicious=malicious,
            model_version=MODEL_VERSION,
            latency_ms=avg_latency,
        )
        rows.append({"url": url, "score": float(prob), "malicious": malicious})

    return pd.DataFrame(rows), threshold, latency_ms


st.header("检测工作台（单条 + 批量）")
col_single, col_batch = st.columns(2)

with col_single:
    st.subheader("单条 URL 检测")
    single_url = st.text_input("输入一个 URL", placeholder="https://example.com/login")
    if st.button("检测单条 URL", type="primary"):
        if not single_url.strip():
            st.warning("请输入 URL")
        else:
            try:
                result_df, threshold, latency_ms = local_detect([single_url.strip()])
                st.caption(f"阈值={threshold:.4f}, 总耗时={latency_ms:.2f} ms")
                st.dataframe(result_df, use_container_width=True)
            except Exception as exc:
                st.error(f"检测失败: {exc}")

with col_batch:
    st.subheader("批量 URL 检测")
    batch_text = st.text_area(
        "每行一个 URL",
        placeholder="https://a.com\nhttps://b.com/login\nhttp://suspicious.xyz/verify",
        height=140,
    )
    if st.button("批量检测 URL"):
        urls = [line.strip() for line in batch_text.splitlines() if line.strip()]
        if not urls:
            st.warning("请至少输入一个 URL")
        elif len(urls) > 200:
            st.warning("单次最多检测 200 条 URL")
        else:
            try:
                result_df, threshold, latency_ms = local_detect(urls)
                st.caption(f"阈值={threshold:.4f}, 样本数={len(urls)}, 总耗时={latency_ms:.2f} ms")
                st.dataframe(result_df, use_container_width=True)
            except Exception as exc:
                st.error(f"批量检测失败: {exc}")

st.header("在线 API 预测监控")
if not os.path.exists(DB_PATH):
    st.warning(f"数据库不存在：{DB_PATH}")
else:
    query = "SELECT ts, url, score, malicious, model_version, latency_ms FROM predictions ORDER BY id DESC LIMIT 5000"
    df = pd.read_sql_query(query, sqlite3.connect(DB_PATH))

    if df.empty:
        st.info("暂无预测数据")
    else:
        df["ts"] = pd.to_datetime(df["ts"])

        col1, col2, col3 = st.columns(3)
        col1.metric("总样本数", len(df))
        col2.metric("恶意判定占比", f"{(df['malicious'].mean() * 100):.2f}%")
        col3.metric("平均延迟(ms)", f"{df['latency_ms'].mean():.2f}")

        st.subheader("延迟趋势")
        st.line_chart(df.sort_values("ts").set_index("ts")["latency_ms"])

        st.subheader("分数分布")
        st.bar_chart(df["score"].round(1).value_counts().sort_index())

        st.subheader("最近预测样本")
        st.dataframe(df.head(200), use_container_width=True)

st.header("离线实验：跨源泛化 / 漂移 / 低误报阈值")
if not os.path.exists(EXPERIMENT_PATH):
    st.info(f"实验报告不存在：{EXPERIMENT_PATH}")
else:
    with open(EXPERIMENT_PATH, "r", encoding="utf-8") as f:
        report = json.load(f)

    setup = report.get("setup", {})
    st.caption(
        f"目标 FPR={setup.get('target_fpr')} | 时间切分训练比例={setup.get('train_ratio')} | "
        f"Train={setup.get('train_samples')} | Test={setup.get('test_samples')}"
    )

    model_rows = []
    source_rows = []
    for model_type, content in report.get("models", {}).items():
        future = content.get("future_window_metrics", {})
        model_rows.append(
            {
                "model_type": model_type,
                "threshold": content.get("threshold_at_target_fpr"),
                "TPR": future.get("tpr"),
                "FPR": future.get("fpr"),
                "ROC-AUC": future.get("roc_auc"),
                "PSI(train->test)": content.get("drift", {}).get("psi_scores_train_vs_test"),
            }
        )
        for source, score in content.get("source_tpr_compare", {}).items():
            source_rows.append(
                {
                    "model_type": model_type,
                    "source": source,
                    "TPR": score.get("tpr"),
                    "FPR": score.get("fpr"),
                    "support": score.get("support"),
                }
            )

    if model_rows:
        st.subheader("固定低 FPR 点的整体对比")
        st.dataframe(pd.DataFrame(model_rows), use_container_width=True)

    if source_rows:
        st.subheader("跨来源 TPR/FPR 对比")
        src_df = pd.DataFrame(source_rows)
        st.dataframe(src_df, use_container_width=True)
        st.bar_chart(src_df.pivot(index="source", columns="model_type", values="TPR"))

    fp_rows = []
    for model_type, content in report.get("models", {}).items():
        for item in content.get("false_positive_samples", []):
            fp_rows.append({"model_type": model_type, **item})

    if fp_rows:
        st.subheader("误报样本分析（Top by score）")
        st.dataframe(pd.DataFrame(fp_rows), use_container_width=True)

    retrain = report.get("retrain_loop", {})
    if retrain:
        st.subheader("再训练闭环效果")
        st.write(
            {
                "hard_negative_count": retrain.get("hard_negative_count"),
                "baseline_tpr": retrain.get("baseline", {}).get("tpr"),
                "baseline_fpr": retrain.get("baseline", {}).get("fpr"),
                "retrained_tpr": retrain.get("retrained", {}).get("tpr"),
                "retrained_fpr": retrain.get("retrained", {}).get("fpr"),
            }
        )
