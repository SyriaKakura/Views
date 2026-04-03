"""FastAPI inference API for malicious URL detection."""

from __future__ import annotations

import os
import time
from functools import lru_cache
from math import exp
from pathlib import Path
from typing import Any

import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.features import legacy_url_features, normalize_url
from app.modeling import train_model
from app.storage import init_db, insert_prediction

MODEL_PATH = os.getenv("MODEL_PATH", "artifacts/url_detector.joblib")
MODEL_VERSION = os.getenv("MODEL_VERSION", "v2.0-logistic-lightgbm")
THRESHOLD = float(os.getenv("THRESHOLD", "-1"))
DB_PATH = os.getenv("DB_PATH", "artifacts/predictions.db")
AUTO_TRAIN_ON_MISSING_MODEL = os.getenv("AUTO_TRAIN_ON_MISSING_MODEL", "1") not in {
    "0",
    "false",
    "False",
}
BOOTSTRAP_DATA_PATH = os.getenv("BOOTSTRAP_DATA_PATH", "data/sample_urls.csv")


def _bootstrap_model_if_needed() -> None:
    if os.path.exists(MODEL_PATH):
        return
    if not AUTO_TRAIN_ON_MISSING_MODEL:
        return
    if not os.path.exists(BOOTSTRAP_DATA_PATH):
        raise FileNotFoundError(
            f"model not found: {MODEL_PATH}; bootstrap dataset not found: {BOOTSTRAP_DATA_PATH}"
        )

    df = pd.read_csv(BOOTSTRAP_DATA_PATH)
    if not {"url", "label"}.issubset(df.columns):
        raise ValueError("Bootstrap dataset must contain columns: url,label")

    Path(MODEL_PATH).parent.mkdir(parents=True, exist_ok=True)
    train_model(
        urls=df["url"].astype(str).tolist(),
        labels=df["label"].astype(int).tolist(),
        model_type="logistic",
        model_path=MODEL_PATH,
    )


class PredictRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=4096)


class PredictResponse(BaseModel):
    malicious: bool
    score: float
    threshold: float
    model_version: str
    latency_ms: float


class BatchRequest(BaseModel):
    urls: list[str] = Field(..., min_length=1, max_length=200)


class BatchItem(BaseModel):
    url: str
    malicious: bool
    score: float


class BatchResponse(BaseModel):
    items: list[BatchItem]
    model_version: str


class ModelInfo(BaseModel):
    model_path: str
    model_version: str
    model_type: str
    threshold: float
    target_fpr: float
    feature_version: str
    trained_at_utc: str


class LegacyDetectRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=4096)


class LegacyBatchRequest(BaseModel):
    urls: list[str] = Field(..., min_length=1, max_length=100)


def _safe_sigmoid(value: float) -> float:
    if value >= 0:
        z = exp(-value)
        return 1.0 / (1.0 + z)
    z = exp(value)
    return z / (1.0 + z)


def _heuristic_score(url: str) -> float:
    feats = legacy_url_features(url)
    score = 0.0
    score += min(feats["suspicious_words_count"] * 0.08, 0.35)
    score += min(feats["suspicious_patterns"] * 0.10, 0.25)
    score += 0.15 if feats["suspicious_tld"] else 0.0
    score += 0.12 if feats["shortened_url"] else 0.0
    score += 0.15 if feats["suspicious_extension"] else 0.0
    score += 0.08 if feats["ip_in_domain"] else 0.0
    score += 0.05 if feats["ssl_certificate"] == 0 else 0.0
    score += min(feats["entropy"] / 12.0, 0.12)
    return float(min(max(score, 0.01), 0.99))


def _predict_score(model: Any, normalized_url: str) -> float:
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba([normalized_url])[0][1]
        score = float(proba)
        if abs(score - 0.5) < 1e-9:
            return _heuristic_score(normalized_url)
        return score

    if hasattr(model, "decision_function"):
        margin = float(model.decision_function([normalized_url])[0])
        return _safe_sigmoid(margin)

    if hasattr(model, "predict"):
        pred = model.predict([normalized_url])[0]
        if isinstance(pred, (bool, int, float)):
            return 0.99 if bool(pred) else 0.01
        legacy = model.predict(normalized_url)
        if isinstance(legacy, dict):
            if "confidence" in legacy:
                return float(legacy["confidence"])
            if "is_malicious" in legacy:
                return 0.99 if bool(legacy["is_malicious"]) else 0.01

    raise RuntimeError("Loaded model does not provide a usable prediction interface")


@lru_cache(maxsize=1)
def get_model_bundle():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"model not found: {MODEL_PATH}")

    obj = joblib.load(MODEL_PATH)
    if isinstance(obj, dict) and "pipeline" in obj:
        return obj

    return {
        "pipeline": obj,
        "meta": {
            "model_type": "legacy",
            "target_fpr": 0.01,
            "threshold": THRESHOLD if THRESHOLD > 0 else 0.5,
        },
    }


app = FastAPI(title="Malicious URL Detector", version="2.0.0")


@app.on_event("startup")
def startup_event() -> None:
    init_db(DB_PATH)
    _bootstrap_model_if_needed()
    get_model_bundle()


@app.post("/api/v1/predict", response_model=PredictResponse)
def predict(req: PredictRequest):
    try:
        bundle = get_model_bundle()
        model = bundle["pipeline"]
        meta = bundle.get("meta", {})

        threshold = THRESHOLD if THRESHOLD > 0 else float(meta.get("threshold", 0.5))
        t0 = time.time()
        normalized_url = normalize_url(req.url)
        score = _predict_score(model, normalized_url)
        malicious = score >= threshold
        latency_ms = (time.time() - t0) * 1000.0

        insert_prediction(
            DB_PATH,
            url=normalized_url,
            score=score,
            malicious=malicious,
            model_version=MODEL_VERSION,
            latency_ms=latency_ms,
        )

        return PredictResponse(
            malicious=malicious,
            score=score,
            threshold=threshold,
            model_version=MODEL_VERSION,
            latency_ms=latency_ms,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {exc}") from exc


@app.post("/api/v1/predict_batch", response_model=BatchResponse)
def predict_batch(req: BatchRequest):
    try:
        bundle = get_model_bundle()
        model = bundle["pipeline"]
        meta = bundle.get("meta", {})
        threshold = THRESHOLD if THRESHOLD > 0 else float(meta.get("threshold", 0.5))

        normalized_urls = [normalize_url(url) for url in req.urls]
        probs = [_predict_score(model, url) for url in normalized_urls]
        items = [
            BatchItem(url=url, malicious=(float(prob) >= threshold), score=float(prob))
            for url, prob in zip(normalized_urls, probs)
        ]
        return BatchResponse(items=items, model_version=MODEL_VERSION)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Batch prediction failed: {exc}") from exc


@app.get("/health")
def health_check():
    try:
        bundle = get_model_bundle()
        loaded = bool(bundle.get("pipeline") is not None)
    except Exception:
        loaded = False
    return {
        "status": "healthy",
        "model_loaded": loaded,
        "model_version": MODEL_VERSION,
    }


@app.get("/api/v1/model_info", response_model=ModelInfo)
def model_info():
    if not os.path.exists(MODEL_PATH):
        raise HTTPException(status_code=404, detail="Model artifact not found")

    meta = get_model_bundle().get("meta", {})
    threshold = THRESHOLD if THRESHOLD > 0 else float(meta.get("threshold", 0.5))
    return ModelInfo(
        model_path=MODEL_PATH,
        model_version=MODEL_VERSION,
        model_type=str(meta.get("model_type", "legacy")),
        threshold=threshold,
        target_fpr=float(meta.get("target_fpr", 0.01)),
        feature_version=str(meta.get("feature_version", "unknown")),
        trained_at_utc=str(meta.get("trained_at_utc", "unknown")),
    )


@app.post("/detect")
def detect_legacy(req: LegacyDetectRequest):
    response = predict(PredictRequest(url=req.url))
    features = legacy_url_features(req.url)
    return {
        "status": "success",
        "result": {
            "url": normalize_url(req.url),
            "is_malicious": bool(response.malicious),
            "confidence": float(response.score),
            "features": features,
        },
    }


@app.post("/batch_detect")
def batch_detect_legacy(req: LegacyBatchRequest):
    batch = predict_batch(BatchRequest(urls=req.urls))
    return {
        "status": "success",
        "total_urls": len(batch.items),
        "results": [
            {
                "url": item.url,
                "is_malicious": bool(item.malicious),
                "confidence": float(item.score),
            }
            for item in batch.items
        ],
    }


@app.post("/features")
def extract_features_legacy(req: LegacyDetectRequest):
    normalized_url = normalize_url(req.url)
    return {
        "status": "success",
        "url": normalized_url,
        "features": legacy_url_features(normalized_url),
    }


@app.get("/stats")
def stats_legacy():
    bundle = get_model_bundle()
    feature_names = sorted(legacy_url_features("https://example.com").keys())
    return {
        "status": "success",
        "model_loaded": bool(bundle.get("pipeline") is not None),
        "feature_count": len(feature_names),
        "features": feature_names,
        "model_version": MODEL_VERSION,
    }
