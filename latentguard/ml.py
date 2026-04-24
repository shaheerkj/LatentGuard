from __future__ import annotations

from .contracts import MLScore, NormalizedRequest


class MLDetector:
    """MVP heuristic surrogate for autoencoder anomaly + HDBSCAN outlier scoring."""

    def __init__(self) -> None:
        self.fail_mode = False

    def set_fail_mode(self, enabled: bool) -> None:
        self.fail_mode = enabled

    def score(self, norm: NormalizedRequest) -> MLScore:
        if self.fail_mode:
            raise RuntimeError("ML service unavailable")

        f = norm.features

        anomaly = min(
            1.0,
            (
                (max(0.0, f["entropy"] - 3.5) * 0.22)
                + (max(0.0, f["special_ratio"] - 0.08) * 2.5)
                + (max(0.0, f["length"] - 300.0) / 900.0)
            ),
        )

        outlier = min(
            1.0,
            (
                (max(0.0, f["token_count"] - 40.0) / 120.0)
                + (max(0.0, f["digit_ratio"] - 0.15) * 1.5)
                + (max(0.0, f["uppercase_ratio"] - 0.30) * 1.2)
            ),
        )

        return MLScore(
            anomaly_score=round(anomaly, 4),
            outlier_score=round(outlier, 4),
            details={
                "model": "mvp-heuristic-ae-hdbscan",
                "feature_snapshot": f,
            },
        )
