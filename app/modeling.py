"""Model pipeline creation, training, and evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

import joblib
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline

from app.features import url_struct_features


class StructFeatureTransformer(BaseEstimator, TransformerMixin):
    """Convert URLs into structural numeric feature matrix."""

    def __init__(self) -> None:
        self.columns_: list[str] = []

    def fit(self, X, y=None):
        feats = [url_struct_features(x) for x in X]
        self.columns_ = sorted(feats[0].keys()) if feats else []
        return self

    def transform(self, X):
        feats = [url_struct_features(x) for x in X]
        if not self.columns_ and feats:
            self.columns_ = sorted(feats[0].keys())
        return np.array(
            [[feat.get(col, 0.0) for col in self.columns_] for feat in feats],
            dtype=np.float32,
        )


@dataclass
class TrainResult:
    model_path: str
    metrics: dict[str, float]


def build_feature_union(max_features: int = 200000) -> FeatureUnion:
    tfidf = TfidfVectorizer(
        analyzer="char",
        ngram_range=(3, 5),
        min_df=2,
        max_features=max_features,
    )
    return FeatureUnion(
        [
            ("tfidf", tfidf),
            ("struct", StructFeatureTransformer()),
        ]
    )


def build_estimator(model_type: str):
    model_type = model_type.lower()
    if model_type == "logistic":
        return LogisticRegression(
            solver="saga",
            max_iter=2000,
            n_jobs=-1,
            class_weight="balanced",
        )

    if model_type == "lightgbm":
        try:
            from lightgbm import LGBMClassifier
        except ImportError as exc:
            raise ImportError("lightgbm not installed. please install requirements.txt") from exc

        return LGBMClassifier(
            n_estimators=300,
            learning_rate=0.05,
            num_leaves=63,
            subsample=0.9,
            colsample_bytree=0.9,
            random_state=42,
            class_weight="balanced",
            n_jobs=-1,
        )

    raise ValueError(f"Unsupported model_type: {model_type}")


def build_pipeline(model_type: str = "logistic", max_features: int = 200000) -> Pipeline:
    return Pipeline([("features", build_feature_union(max_features=max_features)), ("clf", build_estimator(model_type))])


def evaluate_binary(y_true: Sequence[int], probas: np.ndarray, threshold: float = 0.5) -> dict[str, float]:
    preds = (probas >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, preds, labels=[0, 1]).ravel()
    return {
        "accuracy": float(accuracy_score(y_true, preds)),
        "precision": float(precision_score(y_true, preds, zero_division=0)),
        "recall": float(recall_score(y_true, preds, zero_division=0)),
        "f1": float(f1_score(y_true, preds, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, probas)),
        "tp": float(tp),
        "fp": float(fp),
        "fn": float(fn),
        "tn": float(tn),
        "fpr": float(fp / max(fp + tn, 1)),
        "tpr": float(tp / max(tp + fn, 1)),
    }


def threshold_at_fpr(y_true: Sequence[int], probas: np.ndarray, target_fpr: float = 0.01) -> float:
    fpr, _, thresholds = roc_curve(y_true, probas)
    valid = np.where(fpr <= target_fpr)[0]
    if len(valid) == 0:
        return 1.0
    return float(thresholds[valid[-1]])


def predict_scores(model_obj: Any, urls: Sequence[str]) -> np.ndarray:
    if isinstance(model_obj, dict) and "pipeline" in model_obj:
        pipeline = model_obj["pipeline"]
    else:
        pipeline = model_obj
    return pipeline.predict_proba(list(urls))[:, 1]


def train_model(
    urls: Sequence[str],
    labels: Sequence[int],
    model_type: str = "logistic",
    model_path: str = "artifacts/url_detector.joblib",
    target_fpr: float = 0.01,
    test_size: float = 0.2,
    random_state: int = 42,
) -> TrainResult:
    x_train, x_test, y_train, y_test = train_test_split(
        list(urls),
        list(labels),
        test_size=test_size,
        random_state=random_state,
        stratify=labels,
    )

    pipeline = build_pipeline(model_type=model_type)
    pipeline.fit(x_train, y_train)

    probas = pipeline.predict_proba(x_test)[:, 1]
    low_fpr_threshold = threshold_at_fpr(y_test, probas, target_fpr=target_fpr)
    metrics = evaluate_binary(y_test, probas, threshold=low_fpr_threshold)
    metrics["threshold_low_fpr"] = float(low_fpr_threshold)
    metrics["target_fpr"] = float(target_fpr)
    metrics["model_type"] = model_type

    model_obj = {
        "pipeline": pipeline,
        "meta": {
            "model_type": model_type,
            "target_fpr": target_fpr,
            "threshold": low_fpr_threshold,
            "feature_version": "tfidf_char_3_5_plus_struct_v2",
            "trained_at_utc": datetime.now(timezone.utc).isoformat(),
            "train_samples": len(x_train),
            "test_samples": len(x_test),
        },
    }

    Path(model_path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model_obj, model_path)
    return TrainResult(model_path=model_path, metrics=metrics)
