# Questions — machine learning

### Q. Why an autoencoder for anomaly detection?

Autoencoders learn a compressed representation of normal data
unsupervised; reconstruction error spikes for inputs unlike anything
seen during training. We don't have labeled attack data at the scale
needed for supervised methods, but we have plenty of "normal" traffic
(captured via a benign crawler against Juice Shop + CSIC 2010
HTTP traces). Autoencoders fit that data shape perfectly.

### Q. Why dense layers and not a recurrent / transformer model?

The feature vector is fixed-length (7 numeric features) — there's no
sequential structure for an RNN or attention model to exploit. A
dense 7→8→4→8→7 autoencoder is exactly the right size; anything
deeper would overfit on 6 K training samples.

### Q. Why HDBSCAN and not k-means?

Three reasons. We don't know `k` in advance — HDBSCAN discovers
cluster count from data density. It handles noise points explicitly
as a separate class (label = -1), which we use as a strong anomaly
signal. And it's density-based, which matches the irregular,
non-spherical shape of HTTP-request feature space far better than
k-means's spherical assumption.

### Q. Why run HDBSCAN on the autoencoder bottleneck, not on raw features?

HDBSCAN's complexity grows with dimensionality; the AE's 4-dim
bottleneck is a learned non-linear projection that preserves the
structure HDBSCAN cares about while staying cheap to cluster. It also
means the two models agree on what "similar" means — HDBSCAN
operates in the same latent space the AE built.

### Q. What features does your model see?

Seven per request: total length, Shannon entropy, token count,
special-character ratio, digit ratio, uppercase ratio, and a
method-is-POST flag. Computed in `ml/app/features.py` from the
canonicalised URL + body string. Deliberately interpretable —
every feature has a sentence explanation.

### Q. Aren't seven features kind of few?

Yes — that's a real limitation. Documented in
`docs/defense-notes.md` as a deferred AI improvement: adding
character-level n-grams (3-4 grams) would push detection on
obfuscated payloads significantly higher. Today's feature set is
chosen for *interpretability over coverage*, on the principle that
an FYP demo should explain itself.

### Q. How much training data?

6,663 samples in the latest build (`autoencoder.json` shows the
count). Mix of CSIC 2010 normal HTTP traces and a custom benign
crawler that hits the live Juice Shop with realistic flows
(register, login, browse, search, add-to-basket). The crawler runs
inside the bring-up pipeline so the model trains on traffic that
matches the upstream app's actual shape.

### Q. How do you know the autoencoder isn't overfitting?

We track p50, p95, p99 reconstruction error during training; the
inference threshold is set at p99.5 of the training distribution.
Visible in the Anomaly Models tab. Held-out validation isn't
formally split (small dataset, unsupervised problem) — instead we
measure end-to-end TPR/FPR on a separate red-team battery, which
gives an honest functional signal.

### Q. What's the consensus engine actually doing?

Three modes:
- **weighted** — default. `score = w_ae * anomaly + w_hdb * outlier + w_rule * rule_score`, block if `score >= threshold` and any per-component score >= per-model threshold.
- **majority** — block if 2 of 3 components individually exceed per-model threshold.
- **strict** — block only if all 3 components exceed per-model threshold (high precision, low recall).

The operator picks the mode and tunes weights from the dashboard.
Configuration persists to `ml_config` in Mongo and is re-read on
every scoring call.

### Q. Why a configurable consensus instead of a fixed ensemble?

Different operators have different tolerance for false positives.
A bank protecting login endpoints wants `strict`; a media site
serving comments wants `weighted` with a lower threshold. Hard-coding
the mode would force one trade-off on everyone.

### Q. How do you detect concept drift?

`/api/models/drift` computes z-score of the mean autoencoder
anomaly score over the last hour vs the previous 24 h. If
|z| ≥ 2.0 and both windows have ≥30 samples, drift is flagged.
Dashboard topbar pill turns red. This is M11-partial — the
auto-retrain trigger that would close the loop isn't built yet
(deliberately, see `documentation/07-design-decisions.md`).

### Q. Why no auto-retrain on drift?

Because auto-retrain without a poisoning guard is a security
regression. An attacker who can shape the audit log can shift the
training distribution and degrade detection over time. The right
fix is a HITL gate analogous to M10's rule approval, but for
model promotion — that's real engineering work, not a checkbox.

### Q. Why FP-Growth and not Apriori or Eclat?

Apriori re-scans the dataset once per candidate level — exponential
I/O. FP-Growth builds a prefix tree in two passes and recurses,
which is the standard performant choice and matters as the audit
log grows. Eclat would also work but mlxtend's FP-Growth is the
most mature option in the Python ML ecosystem.

### Q. What's the "alphabet" the miner operates over?

Path prefix (first segment), HTTP method, every Coraza attack-rule
ID that fired (scaffold IDs filtered), source /24, AE/HDBSCAN
signal bands (high vs not-high), body-present flag. Deliberately
small and interpretable so every itemset round-trips to a
human-readable rule. Code: `ml/app/mining/miner.py:record_to_items`.

### Q. Why /24 for source IP and not the full IP?

Full-IP frequent itemsets would all have very low support since
attackers rotate IPs. /24 catches "all attacks from this subnet"
which is actionable; finer granularity wouldn't surface in
FP-Growth's frequent set at all.

### Q. What if the miner surfaces patterns from legitimate traffic?

It defaults to `only_blocked=True` — mines only over confirmed-block
audit rows. So even if a benign request matched a pattern, the
miner only sees what consensus already classified as malicious.
Operator approval at M10 is the second filter — they can reject any
candidate that looks too broad.

### Q. How would you measure success of the M9 LLM (when added)?

Three metrics. **Approval rate**: fraction of LLM-drafted rules
that operators approve as-is — proxy for prompt quality. **Edit
distance**: average string diff between draft and approved version —
shows where the LLM consistently gets the syntax wrong. **Block
delta after promotion**: drop in M6-ML-only blocks for the
attack class, since the new rule catches them at M3 — proves the
generated rule is functionally useful.
