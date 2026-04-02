"""FastAPI inference API for malicious URL detection."""

from __future__ import annotations

import os
import time
from functools import lru_cache

import joblib
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.storage import init_db, insert_prediction

MODEL_PATH = os.getenv("MODEL_PATH", "artifacts/url_detector.joblib")
MODEL_VERSION = os.getenv("MODEL_VERSION", "v2.0-logistic-lightgbm")
THRESHOLD = float(os.getenv("THRESHOLD", "-1"))
DB_PATH = os.getenv("DB_PATH", "artifacts/predictions.db")


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
    get_model_bundle()


@app.post("/api/v1/predict", response_model=PredictResponse)
def predict(req: PredictRequest):
    bundle = get_model_bundle()
    model = bundle["pipeline"]
    meta = bundle.get("meta", {})

    threshold = THRESHOLD if THRESHOLD > 0 else float(meta.get("threshold", 0.5))
    t0 = time.time()
    score = float(model.predict_proba([req.url])[0][1])
    malicious = score >= threshold
    latency_ms = (time.time() - t0) * 1000.0

    insert_prediction(
        DB_PATH,
        url=req.url,
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


@app.post("/api/v1/predict_batch", response_model=BatchResponse)
def predict_batch(req: BatchRequest):
    bundle = get_model_bundle()
    model = bundle["pipeline"]
    meta = bundle.get("meta", {})
    threshold = THRESHOLD if THRESHOLD > 0 else float(meta.get("threshold", 0.5))

    probs = model.predict_proba(req.urls)[:, 1].tolist()
    items = [
        BatchItem(url=url, malicious=(float(prob) >= threshold), score=float(prob))
        for url, prob in zip(req.urls, probs)
    ]
    return BatchResponse(items=items, model_version=MODEL_VERSION)


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
    )
