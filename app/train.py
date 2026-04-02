"""CLI training entrypoint."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from app.modeling import train_model


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="CSV path with columns: url,label")
    parser.add_argument("--model-type", default="logistic", choices=["logistic", "lightgbm"])
    parser.add_argument("--model-path", default="artifacts/url_detector.joblib")
    parser.add_argument("--metrics-path", default="artifacts/train_metrics.json")
    parser.add_argument("--target-fpr", type=float, default=0.01)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    df = pd.read_csv(args.input)
    if not {"url", "label"}.issubset(df.columns):
        raise ValueError("Input CSV must contain columns: url,label")

    result = train_model(
        df["url"].astype(str).tolist(),
        df["label"].astype(int).tolist(),
        model_type=args.model_type,
        model_path=args.model_path,
        target_fpr=args.target_fpr,
    )

    Path(args.metrics_path).parent.mkdir(parents=True, exist_ok=True)
    with open(args.metrics_path, "w", encoding="utf-8") as f:
        json.dump(result.metrics, f, ensure_ascii=False, indent=2)

    print("Model saved:", result.model_path)
    print("Metrics:")
    print(json.dumps(result.metrics, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
