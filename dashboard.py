"""Streamlit dashboard for online logs + offline systematic experiment report."""

from __future__ import annotations

import json
import os
import re
import sqlite3
from collections import deque
from html.parser import HTMLParser
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

import pandas as pd
import streamlit as st

DB_PATH = os.getenv("DB_PATH", "artifacts/predictions.db")
EXPERIMENT_PATH = os.getenv("EXPERIMENT_PATH", "artifacts/experiment_report.json")
API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")


class LinkParser(HTMLParser):
    """Simple HTML link parser for extracting href values."""

    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        for key, value in attrs:
            if key.lower() == "href" and value:
                self.hrefs.append(value)


def normalize_http_url(url: str) -> str | None:
    url = url.strip()
    if not url:
        return None
    if not re.match(r"^https?://", url, flags=re.IGNORECASE):
        url = f"http://{url}"

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return None
    if not parsed.netloc:
        return None
    return url


def fetch_page_links(url: str, timeout: float = 6.0) -> list[str]:
    req = Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (compatible; URLDetectorBot/1.0; +https://example.com/bot)"
        },
    )
    with urlopen(req, timeout=timeout) as resp:
        content_type = resp.headers.get("Content-Type", "")
        if "text/html" not in content_type:
            return []
        html = resp.read().decode("utf-8", errors="ignore")

    parser = LinkParser()
    parser.feed(html)
    parser.close()
    return parser.hrefs


def crawl_urls(seed_url: str, max_urls: int, same_domain_only: bool, max_depth: int = 1) -> tuple[list[str], list[str]]:
    """Breadth-first crawl for collecting candidate URLs."""
    normalized_seed = normalize_http_url(seed_url)
    if not normalized_seed:
        return [], ["种子 URL 无效，请输入 http/https URL"]

    seed_host = urlparse(normalized_seed).netloc
    queue: deque[tuple[str, int]] = deque([(normalized_seed, 0)])
    visited: set[str] = set()
    collected: list[str] = []
    errors: list[str] = []

    while queue and len(collected) < max_urls:
        current, depth = queue.popleft()
        if current in visited:
            continue

        visited.add(current)
        collected.append(current)

        if depth >= max_depth:
            continue

        try:
            hrefs = fetch_page_links(current)
        except (HTTPError, URLError, TimeoutError, ValueError) as exc:
            errors.append(f"抓取失败: {current} ({exc})")
            continue

        for href in hrefs:
            candidate = normalize_http_url(urljoin(current, href))
            if not candidate or candidate in visited:
                continue

            if same_domain_only and urlparse(candidate).netloc != seed_host:
                continue

            if len(visited) + len(queue) >= max_urls * 4:
                continue

            queue.append((candidate, depth + 1))

    return collected[:max_urls], errors


def chunked(values: Iterable[str], batch_size: int) -> Iterable[list[str]]:
    batch: list[str] = []
    for value in values:
        batch.append(value)
        if len(batch) >= batch_size:
            yield batch
            batch = []
    if batch:
        yield batch


st.set_page_config(page_title="Malicious URL Detector Dashboard", layout="wide")
st.title("恶意 URL 检测闭环仪表盘")

st.header("可视化 URL 检测")
with st.expander("单条 URL 检测", expanded=True):
    single_url = st.text_input("输入要检测的 URL", placeholder="https://example.com/path")
    if st.button("检测单条 URL"):
        candidate = normalize_http_url(single_url or "")
        if not candidate:
            st.error("URL 格式无效，请输入 http/https 地址")
        else:
            try:
                import requests

                resp = requests.post(f"{API_BASE_URL}/api/v1/predict", json={"url": candidate}, timeout=8)
                resp.raise_for_status()
                data = resp.json()
                st.success("检测完成")
                st.json(data)
            except Exception as exc:
                st.error(f"调用检测接口失败：{exc}")

with st.expander("批量 URL 检测", expanded=True):
    batch_input = st.text_area(
        "每行一个 URL",
        placeholder="https://a.com\nhttps://b.com/login",
        height=140,
    )
    if st.button("检测批量 URL"):
        raw_urls = [line.strip() for line in batch_input.splitlines() if line.strip()]
        urls = [u for u in (normalize_http_url(item) for item in raw_urls) if u]

        if not urls:
            st.warning("没有可检测的有效 URL")
        else:
            try:
                import requests

                all_items = []
                for group in chunked(urls, 200):
                    resp = requests.post(
                        f"{API_BASE_URL}/api/v1/predict_batch",
                        json={"urls": group},
                        timeout=12,
                    )
                    resp.raise_for_status()
                    all_items.extend(resp.json().get("items", []))

                batch_df = pd.DataFrame(all_items)
                st.dataframe(batch_df, use_container_width=True)
                st.download_button(
                    label="下载批量检测结果 CSV",
                    data=batch_df.to_csv(index=False).encode("utf-8"),
                    file_name="batch_detect_result.csv",
                    mime="text/csv",
                )
            except Exception as exc:
                st.error(f"批量检测失败：{exc}")

st.header("网站 URL 批量采集（用于训练/检测）")
col_a, col_b, col_c = st.columns([4, 2, 2])
with col_a:
    seed_url = st.text_input("种子网站 URL", placeholder="https://example.com")
with col_b:
    max_urls = st.number_input("最多采集数量", min_value=10, max_value=5000, value=200, step=10)
with col_c:
    max_depth = st.slider("采集深度", min_value=0, max_value=2, value=1)
same_domain_only = st.checkbox("仅采集同域名 URL", value=True)

if st.button("开始采集 URL"):
    urls, errors = crawl_urls(
        seed_url=seed_url,
        max_urls=int(max_urls),
        same_domain_only=same_domain_only,
        max_depth=max_depth,
    )

    if urls:
        collect_df = pd.DataFrame({"url": urls})
        st.success(f"采集完成，共 {len(collect_df)} 条 URL")
        st.dataframe(collect_df, use_container_width=True)

        default_label = st.selectbox(
            "导出训练样本时的默认标签（0=正常，1=恶意）",
            options=[0, 1],
            index=0,
        )
        train_df = collect_df.copy()
        train_df["label"] = int(default_label)

        st.download_button(
            label="下载采集 URL（仅 URL）",
            data=collect_df.to_csv(index=False).encode("utf-8"),
            file_name="collected_urls.csv",
            mime="text/csv",
        )
        st.download_button(
            label="下载训练文件（url,label）",
            data=train_df.to_csv(index=False).encode("utf-8"),
            file_name="collected_urls_for_train.csv",
            mime="text/csv",
        )

        if st.button("对采集 URL 立即执行批量检测"):
            try:
                import requests

                all_items = []
                for group in chunked(collect_df["url"].tolist(), 200):
                    resp = requests.post(
                        f"{API_BASE_URL}/api/v1/predict_batch",
                        json={"urls": group},
                        timeout=12,
                    )
                    resp.raise_for_status()
                    all_items.extend(resp.json().get("items", []))

                detect_df = pd.DataFrame(all_items)
                st.subheader("采集 URL 检测结果")
                st.dataframe(detect_df, use_container_width=True)
                st.download_button(
                    label="下载采集 URL 检测结果",
                    data=detect_df.to_csv(index=False).encode("utf-8"),
                    file_name="collected_urls_detected.csv",
                    mime="text/csv",
                )
            except Exception as exc:
                st.error(f"采集 URL 批量检测失败：{exc}")

    if errors:
        st.warning("部分页面抓取失败，可忽略非关键页面")
        st.code("\n".join(errors[:20]))

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
        col3.metric("P95 延迟(ms)", f"{df['latency_ms'].quantile(0.95):.2f}")

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
