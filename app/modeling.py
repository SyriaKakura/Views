"""Model pipeline creation, training, and evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

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


def build_logistic_pipeline(max_features: int = 200000) -> Pipeline:
    tfidf = TfidfVectorizer(
        analyzer="char",
        ngram_range=(3, 5),
        min_df=2,
        max_features=max_features,
    )
    features = FeatureUnion(
        [
            ("tfidf", tfidf),
            ("struct", StructFeatureTransformer()),
        ]
    )
    clf = LogisticRegression(
        solver="saga",
        max_iter=2000,
        n_jobs=-1,
        class_weight="balanced",
    )
    return Pipeline([("features", features), ("clf", clf)])


def evaluate_binary(y_true: Sequence[int], probas: np.ndarray, threshold: float = 0.5) -> dict[str, float]:
    preds = (probas >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, preds).ravel()
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
    }


def train_logistic(
    urls: Sequence[str],
    labels: Sequence[int],
    model_path: str = "artifacts/url_detector_logistic.joblib",
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
    pipe = build_logistic_pipeline()
    pipe.fit(x_train, y_train)

    probas = pipe.predict_proba(x_test)[:, 1]
    metrics = evaluate_binary(y_test, probas)

    Path(model_path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipe, model_path)
    return TrainResult(model_path=model_path, metrics=metrics)
