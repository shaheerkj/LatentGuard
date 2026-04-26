"""Lazy loader and scorer for the M4 autoencoder + M5 HDBSCAN.

Design notes:
  - All heavy imports (tensorflow, hdbscan, joblib) are deferred until the
    first call. Cold start of the FastAPI process should not pay for them.
  - If artifacts are missing, score() degrades to zeros and main logs once.
    This keeps the proxy unblocked while the operator trains.
  - Singleton state is module-level (Python guarantees a module is imported
    once per process). FastAPI workers each get their own copy - acceptable
    given model size (~tens of KB).
"""
from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

logger = logging.getLogger("latentguard.ml.models")

MODELS_DIR = Path(__file__).resolve().parents[1] / "models"
AE_PATH = MODELS_DIR / "autoencoder.keras"
AE_SCALER_PATH = MODELS_DIR / "autoencoder_scaler.pkl"
AE_META_PATH = MODELS_DIR / "autoencoder.json"
HDB_PATH = MODELS_DIR / "hdbscan.pkl"
HDB_META_PATH = MODELS_DIR / "hdbscan.json"


@dataclass
class ModelScore:
    anomaly_score: float = 0.0   # M4 autoencoder, normalised to [0,1]
    outlier_score: float = 0.0   # M5 HDBSCAN, normalised to [0,1]
    autoencoder_loaded: bool = False
    hdbscan_loaded: bool = False
    notes: list[str] = None      # human-readable notes for the audit reasons

    def __post_init__(self) -> None:
        if self.notes is None:
            self.notes = []


class _Store:
    """Holds loaded artifacts. Thread-safe lazy init."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._loaded = False
        self.ae_model = None
        self.ae_encoder = None     # truncated to bottleneck, for HDBSCAN input
        self.ae_scaler = None
        self.ae_threshold: float | None = None
        self.ae_meta: dict[str, Any] = {}
        self.hdb_model = None
        self.hdb_meta: dict[str, Any] = {}
        self._warned_missing = False

    def ensure_loaded(self) -> None:
        if self._loaded:
            return
        with self._lock:
            if self._loaded:
                return
            self._load_inner()
            self._loaded = True

    def _load_inner(self) -> None:
        if AE_PATH.exists() and AE_SCALER_PATH.exists():
            try:
                from tensorflow import keras
                import joblib
                self.ae_model = keras.models.load_model(AE_PATH, compile=False)
                self.ae_encoder = keras.Model(
                    self.ae_model.input,
                    self.ae_model.get_layer("bottleneck").output,
                )
                self.ae_scaler = joblib.load(AE_SCALER_PATH)
                if AE_META_PATH.exists():
                    self.ae_meta = json.loads(AE_META_PATH.read_text())
                    self.ae_threshold = float(self.ae_meta.get("threshold", 0.0))
                logger.info("autoencoder loaded: %s", self.ae_meta.get("version", "unknown"))
            except Exception as exc:
                logger.exception("failed to load autoencoder: %s", exc)
                self.ae_model = self.ae_encoder = self.ae_scaler = None
        elif not self._warned_missing:
            logger.warning("autoencoder artifacts missing under %s - operating in stub mode", MODELS_DIR)
            self._warned_missing = True

        if HDB_PATH.exists():
            try:
                import joblib
                self.hdb_model = joblib.load(HDB_PATH)
                if HDB_META_PATH.exists():
                    self.hdb_meta = json.loads(HDB_META_PATH.read_text())
                logger.info("hdbscan loaded: %s", self.hdb_meta.get("version", "unknown"))
            except Exception as exc:
                logger.exception("failed to load hdbscan: %s", exc)
                self.hdb_model = None

    def reload(self) -> None:
        with self._lock:
            self._loaded = False
            self.ae_model = self.ae_encoder = self.ae_scaler = None
            self.ae_meta = {}
            self.ae_threshold = None
            self.hdb_model = None
            self.hdb_meta = {}
        self.ensure_loaded()

    def score(self, features_vec: list[float]) -> ModelScore:
        self.ensure_loaded()
        out = ModelScore()
        x = np.array([features_vec], dtype="float32")

        if self.ae_model is not None and self.ae_scaler is not None:
            xs = self.ae_scaler.transform(x).astype("float32")
            recon = self.ae_model.predict(xs, verbose=0)
            err = float(np.mean(np.square(xs - recon), axis=1)[0])
            thr = self.ae_threshold or 1e-6
            out.anomaly_score = float(min(1.0, err / (2.0 * thr)))
            out.autoencoder_loaded = True
            if err >= thr:
                out.notes.append(f"autoencoder recon error {err:.4f} >= threshold {thr:.4f}")

            if self.hdb_model is not None and self.ae_encoder is not None:
                z = self.ae_encoder.predict(xs, verbose=0)
                try:
                    import hdbscan
                    labels, strengths = hdbscan.approximate_predict(self.hdb_model, z)
                    strength = float(strengths[0])
                    label = int(labels[0])
                    out.outlier_score = float(max(0.0, min(1.0, 1.0 - strength)))
                    if label == -1:
                        out.outlier_score = max(out.outlier_score, 0.75)
                        out.notes.append("hdbscan: noise point")
                    out.hdbscan_loaded = True
                except Exception as exc:
                    logger.warning("hdbscan predict failed: %s", exc)

        return out

    def status(self) -> dict[str, Any]:
        self.ensure_loaded()
        return {
            "autoencoder": {
                "loaded": self.ae_model is not None,
                **self.ae_meta,
            },
            "hdbscan": {
                "loaded": self.hdb_model is not None,
                **self.hdb_meta,
            },
        }


_store: _Store | None = None


def get_store() -> _Store:
    global _store
    if _store is None:
        _store = _Store()
    return _store
