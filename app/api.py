"""FastAPI inference API for malicious URL detection."""

from __future__ import annotations

import os
import time
from functools import lru_cache

import joblib
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, constr

from app.storage import init_db, insert_prediction

MODEL_PATH = os.getenv("MODEL_PATH", "artifacts/url_detector_logistic.joblib")
MODEL_VERSION = os.getenv("MODEL_VERSION", "v1.0-logistic")
DB_PATH = os.getenv("DB_PATH", "artifacts/predictions.db")


def _parse_threshold(raw: str) -> float:
    threshold = float(raw)
    if not 0.0 <= threshold <= 1.0:
        raise ValueError("THRESHOLD must be between 0 and 1")
    return threshold


THRESHOLD = _parse_threshold(os.getenv("THRESHOLD", "0.5"))


UrlInput = constr(strip_whitespace=True, min_length=1, max_length=4096, pattern=r"^[^\x00-\x1F\x7F]+$")


class PredictRequest(BaseModel):
    url: UrlInput


class PredictResponse(BaseModel):
    malicious: bool
    score: float
    threshold: float
    model_version: str
    latency_ms: float


class BatchRequest(BaseModel):
    urls: list[UrlInput] = Field(..., min_length=1, max_length=200)


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
    threshold: float


@lru_cache(maxsize=1)
def get_model():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"model not found: {MODEL_PATH}")
    return joblib.load(MODEL_PATH)


app = FastAPI(title="Malicious URL Detector", version="1.0.0")


@app.on_event("startup")
def startup_event() -> None:
    init_db(DB_PATH)
    get_model()


@app.post("/api/v1/predict", response_model=PredictResponse)
def predict(req: PredictRequest):
    model = get_model()
    t0 = time.time()
    score = float(model.predict_proba([req.url])[0][1])
    malicious = score >= THRESHOLD
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
        threshold=THRESHOLD,
        model_version=MODEL_VERSION,
        latency_ms=latency_ms,
    )


@app.post("/api/v1/predict_batch", response_model=BatchResponse)
def predict_batch(req: BatchRequest):
    model = get_model()
    probs = model.predict_proba(req.urls)[:, 1].tolist()
    items = [
        BatchItem(url=url, malicious=(float(prob) >= THRESHOLD), score=float(prob))
        for url, prob in zip(req.urls, probs)
    ]
    return BatchResponse(items=items, model_version=MODEL_VERSION)


@app.get("/api/v1/model_info", response_model=ModelInfo)
def model_info():
    if not os.path.exists(MODEL_PATH):
        raise HTTPException(status_code=404, detail="Model artifact not found")
    return ModelInfo(model_path=MODEL_PATH, model_version=MODEL_VERSION, threshold=THRESHOLD)
