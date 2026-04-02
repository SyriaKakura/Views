"""FastAPI inference API for malicious URL detection."""

from __future__ import annotations

import os
import time
from functools import lru_cache
from typing import Literal

import joblib
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, model_validator

from app.storage import init_db, insert_prediction

MODEL_PATH = os.getenv("MODEL_PATH", "artifacts/url_detector.joblib")
MODEL_VERSION = os.getenv("MODEL_VERSION", "v2.1-logistic-lightgbm")
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
    threshold: float
    model_version: str


class DetectRequest(BaseModel):
    url: str | None = Field(default=None, min_length=1, max_length=4096)
    urls: list[str] | None = Field(default=None, min_length=1, max_length=200)

    @model_validator(mode="after")
    def check_one_mode(self):
        if bool(self.url) == bool(self.urls):
            raise ValueError("Provide exactly one of `url` or `urls`")
        return self


class DetectResponse(BaseModel):
    mode: Literal["single", "batch"]
    threshold: float
    model_version: str
    items: list[BatchItem]
    latency_ms: float


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


def resolve_threshold(meta: dict) -> float:
    return THRESHOLD if THRESHOLD > 0 else float(meta.get("threshold", 0.5))


def score_urls(urls: list[str]) -> tuple[list[float], float, float]:
    bundle = get_model_bundle()
    model = bundle["pipeline"]
    meta = bundle.get("meta", {})
    threshold = resolve_threshold(meta)

    t0 = time.time()
    probs = model.predict_proba(urls)[:, 1].tolist()
    latency_ms = (time.time() - t0) * 1000.0
    return [float(p) for p in probs], threshold, latency_ms


def log_predictions(urls: list[str], probs: list[float], threshold: float, latency_ms: float) -> None:
    each_latency = latency_ms / max(len(urls), 1)
    for url, score in zip(urls, probs):
        insert_prediction(
            DB_PATH,
            url=url,
            score=score,
            malicious=(score >= threshold),
            model_version=MODEL_VERSION,
            latency_ms=each_latency,
        )


app = FastAPI(title="Malicious URL Detector", version="2.1.0")


@app.on_event("startup")
def startup_event() -> None:
    init_db(DB_PATH)
    get_model_bundle()


@app.post("/api/v1/predict", response_model=PredictResponse)
def predict(req: PredictRequest):
    probs, threshold, latency_ms = score_urls([req.url])
    score = probs[0]

    log_predictions([req.url], probs, threshold, latency_ms)

    return PredictResponse(
        malicious=(score >= threshold),
        score=score,
        threshold=threshold,
        model_version=MODEL_VERSION,
        latency_ms=latency_ms,
    )


@app.post("/api/v1/predict_batch", response_model=BatchResponse)
def predict_batch(req: BatchRequest):
    probs, threshold, latency_ms = score_urls(req.urls)
    log_predictions(req.urls, probs, threshold, latency_ms)

    items = [BatchItem(url=url, malicious=(prob >= threshold), score=prob) for url, prob in zip(req.urls, probs)]
    return BatchResponse(items=items, threshold=threshold, model_version=MODEL_VERSION)


@app.post("/api/v1/detect", response_model=DetectResponse)
def detect(req: DetectRequest):
    urls = [req.url] if req.url else list(req.urls or [])
    probs, threshold, latency_ms = score_urls(urls)
    log_predictions(urls, probs, threshold, latency_ms)

    items = [BatchItem(url=url, malicious=(prob >= threshold), score=prob) for url, prob in zip(urls, probs)]
    mode: Literal["single", "batch"] = "single" if req.url else "batch"
    return DetectResponse(
        mode=mode,
        threshold=threshold,
        model_version=MODEL_VERSION,
        items=items,
        latency_ms=latency_ms,
    )


@app.get("/api/v1/model_info", response_model=ModelInfo)
def model_info():
    if not os.path.exists(MODEL_PATH):
        raise HTTPException(status_code=404, detail="Model artifact not found")

    meta = get_model_bundle().get("meta", {})
    threshold = resolve_threshold(meta)
    return ModelInfo(
        model_path=MODEL_PATH,
        model_version=MODEL_VERSION,
        model_type=str(meta.get("model_type", "legacy")),
        threshold=threshold,
        target_fpr=float(meta.get("target_fpr", 0.01)),
    )
