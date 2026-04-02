"""Systematic experiments for cross-source generalization, drift and low-FPR thresholding."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, roc_auc_score

from app.modeling import threshold_at_fpr, train_model


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="CSV with columns: url,label and optional source,ts")
    parser.add_argument("--output", default="artifacts/experiment_report.json")
    parser.add_argument("--fp-output", default="artifacts/false_positive_cases.csv")
    parser.add_argument("--time-col", default="ts")
    parser.add_argument("--source-col", default="source")
    parser.add_argument("--target-fpr", type=float, default=0.01)
    parser.add_argument("--train-ratio", type=float, default=0.7)
    return parser.parse_args()


def _infer_source(url: str) -> str:
    host = (urlsplit(url if "://" in url else f"http://{url}").hostname or "unknown").lower()
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def _prepare_dataframe(df: pd.DataFrame, source_col: str, time_col: str) -> pd.DataFrame:
    out = df.copy()
    if source_col not in out.columns:
        out[source_col] = out["url"].astype(str).map(_infer_source)

    if time_col in out.columns:
        out[time_col] = pd.to_datetime(out[time_col], errors="coerce")
        out = out.sort_values(time_col).reset_index(drop=True)
        out["_time_key"] = out[time_col].ffill().bfill()
    else:
        out["_time_key"] = pd.date_range("2025-01-01", periods=len(out), freq="h")

    return out


def _psi(a: np.ndarray, b: np.ndarray, bins: int = 10) -> float:
    quantiles = np.linspace(0, 1, bins + 1)
    edges = np.quantile(a, quantiles)
    edges = np.unique(edges)
    if len(edges) < 3:
        return 0.0

    a_hist, _ = np.histogram(a, bins=edges)
    b_hist, _ = np.histogram(b, bins=edges)

    a_dist = np.clip(a_hist / max(a_hist.sum(), 1), 1e-6, None)
    b_dist = np.clip(b_hist / max(b_hist.sum(), 1), 1e-6, None)
    return float(np.sum((a_dist - b_dist) * np.log(a_dist / b_dist)))


def _metrics_at_threshold(y: np.ndarray, probs: np.ndarray, threshold: float) -> dict[str, float | str | bool]:
    y = np.asarray(y).astype(int)
    probs = np.asarray(probs).astype(float)
    preds = (probs >= threshold).astype(int)

    labels = np.unique(y)
    out: dict[str, float | str | bool] = {
        "support": float(len(y)),
        "positive_count": float((y == 1).sum()),
        "negative_count": float((y == 0).sum()),
    }

    if labels.size < 2:
        out.update(
            {
                "tp": 0.0,
                "fp": 0.0,
                "fn": 0.0,
                "tn": 0.0,
                "tpr": float("nan"),
                "fpr": float("nan"),
                "precision": float("nan"),
                "recall": float("nan"),
                "f1": float("nan"),
                "accuracy": float((preds == y).mean() if len(y) else 0.0),
                "roc_auc": float("nan"),
                "single_class_slice": True,
                "status": "skipped_single_class_slice",
            }
        )
        return out

    tn, fp, fn, tp = confusion_matrix(y, preds, labels=[0, 1]).ravel()
    precision = float(tp / max(tp + fp, 1))
    recall = float(tp / max(tp + fn, 1))
    f1 = float(0.0 if (precision + recall) == 0 else 2 * precision * recall / (precision + recall))

    out.update(
        {
            "tp": float(tp),
            "fp": float(fp),
            "fn": float(fn),
            "tn": float(tn),
            "accuracy": float((preds == y).mean()),
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "roc_auc": float(roc_auc_score(y, probs)),
            "fpr": float(fp / max(fp + tn, 1)),
            "tpr": float(tp / max(tp + fn, 1)),
            "single_class_slice": False,
            "status": "ok",
        }
    )
    return out


def run_experiment(df: pd.DataFrame, target_fpr: float, train_ratio: float, source_col: str) -> dict[str, Any]:
    split_idx = max(1, int(len(df) * train_ratio))
    train_df = df.iloc[:split_idx].copy()
    test_df = df.iloc[split_idx:].copy()

    if train_df[source_col].nunique() < 2 or test_df[source_col].nunique() < 2:
        raise ValueError("Need at least two sources in both train and test segments for cross-source experiment")

    report: dict[str, Any] = {
        "setup": {
            "target_fpr": target_fpr,
            "train_ratio": train_ratio,
            "train_samples": int(len(train_df)),
            "test_samples": int(len(test_df)),
            "train_sources": sorted(train_df[source_col].astype(str).unique().tolist()),
            "test_sources": sorted(test_df[source_col].astype(str).unique().tolist()),
        },
        "models": {},
    }

    for model_type in ["logistic", "lightgbm"]:
        model_path = f"artifacts/{model_type}_experiment_model.joblib"
        train_result = train_model(
            train_df["url"].astype(str).tolist(),
            train_df["label"].astype(int).tolist(),
            model_type=model_type,
            model_path=model_path,
            target_fpr=target_fpr,
            test_size=0.25,
            random_state=42,
        )

        import joblib

        bundle = joblib.load(model_path)
        pipe = bundle["pipeline"]

        train_probs = pipe.predict_proba(train_df["url"].astype(str).tolist())[:, 1]
        test_probs = pipe.predict_proba(test_df["url"].astype(str).tolist())[:, 1]
        threshold = threshold_at_fpr(train_df["label"].astype(int).to_numpy(), train_probs, target_fpr=target_fpr)

        source_cmp = {}
        skipped_sources: list[dict[str, Any]] = []
        for source, group in test_df.groupby(source_col):
            group_probs = pipe.predict_proba(group["url"].astype(str).tolist())[:, 1]
            sm = _metrics_at_threshold(group["label"].astype(int).to_numpy(), group_probs, threshold)
            if bool(sm.get("single_class_slice")):
                skipped_sources.append(
                    {
                        "source": str(source),
                        "support": int(len(group)),
                        "positive_count": int((group["label"].astype(int) == 1).sum()),
                        "negative_count": int((group["label"].astype(int) == 0).sum()),
                        "reason": "single_class_slice",
                    }
                )
                continue
            source_cmp[str(source)] = sm

        fp_mask = (test_df["label"].to_numpy() == 0) & (test_probs >= threshold)
        fp_cases = test_df.loc[fp_mask, ["url", source_col]].copy()
        fp_cases["score"] = test_probs[fp_mask]
        fp_cases["model_type"] = model_type
        fp_cases = fp_cases.sort_values("score", ascending=False).head(30)

        drift = {
            "psi_scores_train_vs_test": _psi(train_probs, test_probs),
            "base_rate_train": float(train_df["label"].mean()),
            "base_rate_test": float(test_df["label"].mean()),
        }

        report["models"][model_type] = {
            "train_metrics": train_result.metrics,
            "threshold_at_target_fpr": threshold,
            "future_window_metrics": _metrics_at_threshold(test_df["label"].astype(int).to_numpy(), test_probs, threshold),
            "source_tpr_compare": {
                source: {"tpr": values["tpr"], "fpr": values["fpr"], "support": int(values["support"])}
                for source, values in source_cmp.items()
            },
            "skipped_single_class_sources": skipped_sources,
            "drift": drift,
            "false_positive_samples": fp_cases.to_dict(orient="records"),
        }

    return report


def run_retrain_loop(df: pd.DataFrame, source_col: str, target_fpr: float, train_ratio: float) -> dict[str, Any]:
    split_idx = max(1, int(len(df) * train_ratio))
    train_df = df.iloc[:split_idx].copy()
    test_df = df.iloc[split_idx:].copy()

    train_model(
        train_df["url"].astype(str).tolist(),
        train_df["label"].astype(int).tolist(),
        model_type="logistic",
        model_path="artifacts/retrain_baseline.joblib",
        target_fpr=target_fpr,
    )

    import joblib

    base_bundle = joblib.load("artifacts/retrain_baseline.joblib")
    base_pipe = base_bundle["pipeline"]
    base_train_probs = base_pipe.predict_proba(train_df["url"].astype(str).tolist())[:, 1]
    base_test_probs = base_pipe.predict_proba(test_df["url"].astype(str).tolist())[:, 1]
    threshold = threshold_at_fpr(train_df["label"].to_numpy(), base_train_probs, target_fpr=target_fpr)

    fp_mask = (test_df["label"].to_numpy() == 0) & (base_test_probs >= threshold)
    hard_neg = test_df.loc[fp_mask, ["url", "label", source_col]].copy()

    if not hard_neg.empty:
        hard_neg["label"] = 0
        expanded_train = pd.concat([train_df[["url", "label", source_col]], hard_neg], ignore_index=True)
    else:
        expanded_train = train_df[["url", "label", source_col]].copy()

    train_model(
        expanded_train["url"].astype(str).tolist(),
        expanded_train["label"].astype(int).tolist(),
        model_type="logistic",
        model_path="artifacts/retrain_loop.joblib",
        target_fpr=target_fpr,
    )

    eval_mask = ~fp_mask
    eval_df = test_df.loc[eval_mask].copy()
    if eval_df.empty:
        eval_df = test_df.copy()

    retrain_bundle = joblib.load("artifacts/retrain_loop.joblib")
    retrain_pipe = retrain_bundle["pipeline"]
    rt_train_probs = retrain_pipe.predict_proba(expanded_train["url"].astype(str).tolist())[:, 1]
    rt_eval_probs = retrain_pipe.predict_proba(eval_df["url"].astype(str).tolist())[:, 1]
    base_eval_probs = base_pipe.predict_proba(eval_df["url"].astype(str).tolist())[:, 1]

    rt_threshold = threshold_at_fpr(expanded_train["label"].to_numpy(), rt_train_probs, target_fpr=target_fpr)

    return {
        "hard_negative_count": int(len(hard_neg)),
        "evaluation_excludes_hard_negatives": True,
        "evaluation_samples": int(len(eval_df)),
        "excluded_samples": int(fp_mask.sum()),
        "baseline": _metrics_at_threshold(eval_df["label"].to_numpy(), base_eval_probs, threshold),
        "retrained": _metrics_at_threshold(eval_df["label"].to_numpy(), rt_eval_probs, rt_threshold),
        "baseline_threshold": threshold,
        "retrained_threshold": rt_threshold,
    }


def main() -> None:
    args = parse_args()
    df = pd.read_csv(args.input)
    if not {"url", "label"}.issubset(df.columns):
        raise ValueError("Input CSV must contain columns: url,label")

    data = _prepare_dataframe(df, source_col=args.source_col, time_col=args.time_col)
    report = run_experiment(data, target_fpr=args.target_fpr, train_ratio=args.train_ratio, source_col=args.source_col)
    report["retrain_loop"] = run_retrain_loop(data, source_col=args.source_col, target_fpr=args.target_fpr, train_ratio=args.train_ratio)

    all_fp = []
    for model_type, content in report["models"].items():
        for item in content["false_positive_samples"]:
            item["model_type"] = model_type
            all_fp.append(item)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    pd.DataFrame(all_fp).to_csv(args.fp_output, index=False)
    print(json.dumps(report["setup"], ensure_ascii=False, indent=2))
    print(f"Saved report => {args.output}")
    print(f"Saved false positive samples => {args.fp_output}")


if __name__ == "__main__":
    main()
