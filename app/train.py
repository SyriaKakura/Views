"""CLI training entrypoint."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from app.modeling import train_logistic


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="CSV path with columns: url,label")
    parser.add_argument("--model-path", default="artifacts/url_detector_logistic.joblib")
    parser.add_argument("--metrics-path", default="artifacts/train_metrics.json")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    df = pd.read_csv(args.input)
    if not {"url", "label"}.issubset(df.columns):
        raise ValueError("Input CSV must contain columns: url,label")

    result = train_logistic(df["url"].astype(str).tolist(), df["label"].astype(int).tolist(), model_path=args.model_path)

    Path(args.metrics_path).parent.mkdir(parents=True, exist_ok=True)
    with open(args.metrics_path, "w", encoding="utf-8") as f:
        json.dump(result.metrics, f, ensure_ascii=False, indent=2)

    print("Model saved:", result.model_path)
    print("Metrics:")
    print(json.dumps(result.metrics, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
