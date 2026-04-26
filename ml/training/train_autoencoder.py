"""Train M4 autoencoder on CSIC 2010 benign traffic.

Outputs (under ml/models/):
  autoencoder.keras       - full Keras model (encoder + decoder)
  autoencoder_scaler.pkl  - StandardScaler fit on training features
  autoencoder.json        - metadata: version, trained_at, samples, threshold,
                            recon_error_p50/p95/p99

Threshold defaults to the 95th percentile of training reconstruction error -
i.e. on benign traffic alone the model would flag ~5% as 'anomalous'. The
consensus engine moderates this with the rule signal, so a slightly hot
autoencoder is fine.

Run:
  cd ml && python -m training.train_autoencoder            # full benign split
  cd ml && python -m training.train_autoencoder --max 2000 # smoke test
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ML_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ML_DIR))

import os  # noqa: E402

import numpy as np  # noqa: E402

from app.features import FEATURE_NAMES, features_matrix  # noqa: E402
from training.csic_loader import CSIC_NORMAL_URL, load_split  # noqa: E402

MODELS_DIR = ML_DIR / "models"
# CSIC_DIR can be overridden so the container can mount the host's cached
# downloads instead of refetching every retrain.
RAW_DIR = Path(os.environ.get("CSIC_DIR", str(ML_DIR.parent / "datasets" / "raw")))
BENIGN_FILE = RAW_DIR / "csic_normal.txt"

DEFAULT_BOTTLENECK = 4
DEFAULT_EPOCHS = 50
DEFAULT_BATCH = 128


def build_autoencoder(input_dim: int, bottleneck: int):
    from tensorflow import keras
    from tensorflow.keras import layers

    inp = keras.Input(shape=(input_dim,), name="features")
    x = layers.Dense(16, activation="relu")(inp)
    x = layers.Dense(8, activation="relu")(x)
    z = layers.Dense(bottleneck, activation="relu", name="bottleneck")(x)
    x = layers.Dense(8, activation="relu")(z)
    x = layers.Dense(16, activation="relu")(x)
    out = layers.Dense(input_dim, activation="linear", name="reconstruction")(x)
    model = keras.Model(inp, out, name="latentguard_autoencoder")
    model.compile(optimizer=keras.optimizers.Adam(1e-3), loss="mse")
    return model


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--max", type=int, default=None, help="cap benign samples (smoke test)")
    p.add_argument("--epochs", type=int, default=DEFAULT_EPOCHS)
    p.add_argument("--batch", type=int, default=DEFAULT_BATCH)
    p.add_argument("--bottleneck", type=int, default=DEFAULT_BOTTLENECK)
    p.add_argument("--threshold-pct", type=float, default=99.0,
                   help="reconstruction-error percentile used as anomaly threshold")
    args = p.parse_args()

    print(f"[autoencoder] loading benign split (max={args.max}) ...", flush=True)
    feats = load_split(BENIGN_FILE, CSIC_NORMAL_URL, max_samples=args.max)
    if not feats:
        print("[autoencoder] ERROR: no samples parsed", file=sys.stderr)
        return 1
    X = features_matrix(feats)
    print(f"[autoencoder] X shape {X.shape}, feature names {FEATURE_NAMES}", flush=True)

    # MinMaxScaler over StandardScaler/RobustScaler:
    # CSIC features (entropy, digit_ratio, special_ratio) have tiny variance, so
    # variance-based scalers turn benign drift into 5+ sigma anomalies. Worse,
    # any clip-to-fixed-range turns out-of-IQR rows into all-saturated vectors
    # the model never trained on -> recon error explodes. MinMax maps to [0,1]
    # using training min/max; out-of-distribution values drift slightly past 0/1
    # but never trigger saturation pathology. Threshold then calibrates against
    # the reconstruction error distribution the model actually learns.
    from sklearn.preprocessing import MinMaxScaler
    scaler = MinMaxScaler()
    Xs = scaler.fit_transform(X).astype("float32")

    from tensorflow import keras
    keras.utils.set_random_seed(42)

    model = build_autoencoder(input_dim=Xs.shape[1], bottleneck=args.bottleneck)
    model.summary(print_fn=lambda s: print("  " + s))

    es = keras.callbacks.EarlyStopping(monitor="val_loss", patience=5, restore_best_weights=True)
    model.fit(
        Xs, Xs,
        epochs=args.epochs,
        batch_size=args.batch,
        validation_split=0.1,
        shuffle=True,
        verbose=2,
        callbacks=[es],
    )

    recon = model.predict(Xs, batch_size=512, verbose=0)
    errors = np.mean(np.square(Xs - recon), axis=1)
    p50, p95, p99 = (float(np.percentile(errors, q)) for q in (50, 95, 99))
    threshold = float(np.percentile(errors, args.threshold_pct))

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    model_path = MODELS_DIR / "autoencoder.keras"
    scaler_path = MODELS_DIR / "autoencoder_scaler.pkl"
    meta_path = MODELS_DIR / "autoencoder.json"

    model.save(model_path)
    import joblib
    joblib.dump(scaler, scaler_path)

    meta = {
        "version": datetime.now(timezone.utc).strftime("ae-%Y%m%d-%H%M%S"),
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "samples": int(Xs.shape[0]),
        "feature_names": list(FEATURE_NAMES),
        "bottleneck": args.bottleneck,
        "threshold": threshold,
        "threshold_percentile": args.threshold_pct,
        "recon_error_p50": p50,
        "recon_error_p95": p95,
        "recon_error_p99": p99,
        "epochs_run": int(len(model.history.epoch)) if model.history else args.epochs,
    }
    meta_path.write_text(json.dumps(meta, indent=2))

    print(f"[autoencoder] saved {model_path.name}, scaler, metadata.")
    print(f"[autoencoder] threshold (p{args.threshold_pct:.0f}) = {threshold:.6f}")
    print(f"[autoencoder] recon error p50/p95/p99 = {p50:.6f}/{p95:.6f}/{p99:.6f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
