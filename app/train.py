"""CLI training entrypoint."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from app.data_prep import prepare_dataset
from app.modeling import train_model


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        action="append",
        default=[],
        help="CSV path with columns: url,label. Can be specified multiple times.",
    )
    parser.add_argument(
        "--input-glob",
        action="append",
        default=[],
        help="Glob pattern(s) used to collect multiple CSV datasets (e.g. data/*.csv).",
    )
    parser.add_argument(
        "--input-dir",
        action="append",
        default=[],
        help="Directory path(s); all *.csv files in each directory are included as training data sources.",
    )
    parser.add_argument("--model-type", default="logistic", choices=["logistic", "lightgbm"])
    parser.add_argument("--model-path", default="artifacts/url_detector.joblib")
    parser.add_argument("--metrics-path", default="artifacts/train_metrics.json")
    parser.add_argument("--target-fpr", type=float, default=0.01)
    args = parser.parse_args()
    if not args.input and not args.input_glob and not args.input_dir:
        parser.error("At least one training data source is required via --input/--input-glob/--input-dir")
    return args


def _collect_input_files(args: argparse.Namespace) -> list[Path]:
    files: list[Path] = []
    seen: set[Path] = set()

    for item in args.input:
        path = Path(item).expanduser()
        if not path.exists():
            raise FileNotFoundError(f"input file not found: {path}")
        if path.is_dir():
            raise ValueError(f"--input expects a file path, got directory: {path}")
        resolved = path.resolve()
        if resolved not in seen:
            seen.add(resolved)
            files.append(resolved)

    for pattern in args.input_glob:
        for path in sorted(Path().glob(pattern)):
            if not path.is_file():
                continue
            resolved = path.resolve()
            if resolved not in seen:
                seen.add(resolved)
                files.append(resolved)

    for directory in args.input_dir:
        base = Path(directory).expanduser()
        if not base.exists():
            raise FileNotFoundError(f"input directory not found: {base}")
        if not base.is_dir():
            raise ValueError(f"--input-dir expects a directory, got file: {base}")
        for path in sorted(base.glob("*.csv")):
            if not path.is_file():
                continue
            resolved = path.resolve()
            if resolved not in seen:
                seen.add(resolved)
                files.append(resolved)

    if not files:
        raise ValueError("No CSV files were discovered from the provided input arguments")
    return files


def main() -> None:
    args = parse_args()
    input_files = _collect_input_files(args)
    frames: list[pd.DataFrame] = []
    for file_path in input_files:
        src_df = pd.read_csv(file_path)
        if "source" not in src_df.columns:
            src_df = src_df.copy()
            src_df["source"] = file_path.stem
        frames.append(src_df)

    df = pd.concat(frames, ignore_index=True)
    prepared = prepare_dataset(df, deduplicate=True)
    clean_df = prepared.frame

    result = train_model(
        clean_df["url"].astype(str).tolist(),
        clean_df["label"].astype(int).tolist(),
        model_type=args.model_type,
        model_path=args.model_path,
        target_fpr=args.target_fpr,
    )

    Path(args.metrics_path).parent.mkdir(parents=True, exist_ok=True)
    with open(args.metrics_path, "w", encoding="utf-8") as f:
        json.dump(result.metrics, f, ensure_ascii=False, indent=2)

    print("Model saved:", result.model_path)
    print("Data sources:", json.dumps([str(path) for path in input_files], ensure_ascii=False))
    print(
        "Data prep:",
        json.dumps(
            {
                "rows_before_cleaning": len(df),
                "rows_after_cleaning": len(clean_df),
                "dropped_rows": prepared.dropped_rows,
                "duplicate_rows_removed": prepared.duplicate_rows,
            },
            ensure_ascii=False,
        ),
    )
    print("Metrics:")
    print(json.dumps(result.metrics, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
