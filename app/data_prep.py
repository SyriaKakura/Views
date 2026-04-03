"""Dataset preparation utilities for robust training/evaluation."""

from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

from app.features import normalize_url


@dataclass
class PreparedDataset:
    frame: pd.DataFrame
    dropped_rows: int
    duplicate_rows: int


def prepare_dataset(
    df: pd.DataFrame,
    *,
    url_col: str = "url",
    label_col: str = "label",
    source_col: str | None = "source",
    ts_col: str | None = "ts",
    deduplicate: bool = True,
) -> PreparedDataset:
    """Clean and normalize input frame for stable model quality."""
    required = {url_col, label_col}
    if not required.issubset(df.columns):
        raise ValueError(f"Input CSV must contain columns: {','.join(sorted(required))}")

    out = df.copy()
    before = len(out)
    out[url_col] = out[url_col].astype(str).map(normalize_url)
    out[label_col] = out[label_col].astype(int)
    out = out.dropna(subset=[url_col, label_col])
    out = out[out[url_col].str.len() > 0]
    dropped_rows = before - len(out)

    duplicate_rows = 0
    if deduplicate:
        dedupe_cols = [url_col, label_col]
        if source_col and source_col in out.columns:
            dedupe_cols.append(source_col)
        out_before = len(out)
        out = out.drop_duplicates(subset=dedupe_cols)
        duplicate_rows = out_before - len(out)

    if ts_col and ts_col in out.columns:
        out[ts_col] = pd.to_datetime(out[ts_col], errors="coerce")
        out = out.sort_values(ts_col).reset_index(drop=True)

    return PreparedDataset(frame=out, dropped_rows=dropped_rows, duplicate_rows=duplicate_rows)

