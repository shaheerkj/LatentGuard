"""Fit M5 HDBSCAN on the autoencoder bottleneck projection of CSIC benign.

Why the bottleneck and not raw features:
  - The 4D latent space is dense and roughly normalised, so HDBSCAN's
    density estimates are stable. Raw features have wildly different scales
    (length in [0, 10k], ratios in [0, 1]) which destabilise it.
  - Reuses the autoencoder's representation, so M4 and M5 stay aligned and a
    re-trained autoencoder automatically updates the latent space M5 sees.

Outputs (under ml/models/):
  hdbscan.pkl      - fit HDBSCAN clusterer with prediction_data=True
  hdbscan.json     - metadata: version, trained_at, samples, n_clusters, n_noise

Run:
  cd ml && python -m training.train_hdbscan
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ML_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ML_DIR))

import os  # noqa: E402

import numpy as np  # noqa: E402

from app.features import features_matrix  # noqa: E402
from training.csic_loader import CSIC_NORMAL_URL, load_split  # noqa: E402
from training.mongo_loader import DEFAULT_UA as CRAWLER_UA, load_by_user_agent  # noqa: E402

MODELS_DIR = ML_DIR / "models"
RAW_DIR = Path(os.environ.get("CSIC_DIR", str(ML_DIR.parent / "datasets" / "raw")))
BENIGN_FILE = RAW_DIR / "csic_normal.txt"


def encode_bottleneck(model, Xs):
    from tensorflow import keras
    enc = keras.Model(model.input, model.get_layer("bottleneck").output)
    return enc.predict(Xs, batch_size=512, verbose=0)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--max", type=int, default=None)
    p.add_argument("--min-cluster-size", type=int, default=20)
    p.add_argument("--min-samples", type=int, default=5)
    p.add_argument("--augment-mongo", action="store_true",
                   help="mix in benign-features rows from the Mongo audit log "
                        "(populated by datasets/crawl_dvwa_benign.py)")
    p.add_argument("--mongo-ua", default=CRAWLER_UA)
    p.add_argument("--mongo-limit", type=int, default=None)
    args = p.parse_args()

    ae_path = MODELS_DIR / "autoencoder.keras"
    scaler_path = MODELS_DIR / "autoencoder_scaler.pkl"
    if not ae_path.exists() or not scaler_path.exists():
        print("[hdbscan] ERROR: train autoencoder first.", file=sys.stderr)
        return 1

    print(f"[hdbscan] loading benign split (max={args.max}) ...", flush=True)
    feats = load_split(BENIGN_FILE, CSIC_NORMAL_URL, max_samples=args.max)

    if args.augment_mongo:
        print(f"[hdbscan] loading Mongo augment (UA={args.mongo_ua}) ...", flush=True)
        extra = load_by_user_agent(args.mongo_ua, limit=args.mongo_limit)
        print(f"[hdbscan] augment: +{len(extra)} rows from audit log", flush=True)
        feats = feats + extra

    X = features_matrix(feats)

    import joblib
    scaler = joblib.load(scaler_path)
    Xs = scaler.transform(X).astype("float32")

    from tensorflow import keras
    model = keras.models.load_model(ae_path, compile=False)

    Z = encode_bottleneck(model, Xs)
    print(f"[hdbscan] bottleneck shape {Z.shape}", flush=True)

    import hdbscan
    t0 = time.perf_counter()
    clusterer = hdbscan.HDBSCAN(
        min_cluster_size=args.min_cluster_size,
        min_samples=args.min_samples,
        prediction_data=True,
        core_dist_n_jobs=1,
    )
    labels = clusterer.fit_predict(Z)
    fit_seconds = round(time.perf_counter() - t0, 2)

    n_clusters = int(len(set(labels)) - (1 if -1 in labels else 0))
    n_noise = int(np.sum(labels == -1))
    print(f"[hdbscan] clusters={n_clusters}, noise={n_noise}/{len(labels)}, fit={fit_seconds}s")

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    pkl_path = MODELS_DIR / "hdbscan.pkl"
    meta_path = MODELS_DIR / "hdbscan.json"
    joblib.dump(clusterer, pkl_path)

    meta = {
        "version": datetime.now(timezone.utc).strftime("hdb-%Y%m%d-%H%M%S"),
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "samples": int(len(labels)),
        "n_clusters": n_clusters,
        "n_noise": n_noise,
        "noise_ratio": round(n_noise / max(len(labels), 1), 4),
        "min_cluster_size": args.min_cluster_size,
        "min_samples": args.min_samples,
        "fit_seconds": fit_seconds,
        "augmented_with_mongo": bool(args.augment_mongo),
    }
    meta_path.write_text(json.dumps(meta, indent=2))

    print(f"[hdbscan] saved {pkl_path.name} + metadata.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
