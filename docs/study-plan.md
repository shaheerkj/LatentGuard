# Study plan — end-to-end, for anyone joining the project

Audience: FYP students. Read this cold and
you should know (a) what LatentGuard is, (b) what we're trying to
publish, (c) what to study to defend it in viva and survive paper
review. No prior context required.

Estimated total: **~4-6 weeks at 2-3 hrs/day** if you already code Python.

---

## Part 1 — what LatentGuard actually is (read first)

**LatentGuard is an Adaptive Dual-Layer Web Application Firewall.**
A Web Application Firewall (WAF) sits in front of a web app and blocks
malicious HTTP requests (SQL injection, XSS, etc.) before they reach
the app. Most WAFs are *rule-based* (regex patterns written by humans).
Ours combines that with *machine learning* and a feedback loop that
**generates new rules from observed attacks**.

### The 3-layer pipeline (every request walks through this)

```
client → [Go reverse proxy] → [Coraza WAF + OWASP CRS rules]
                                          │
                                          ▼
                              [Python ML service]
                              ├── Autoencoder (anomaly score)
                              ├── HDBSCAN (cluster-outlier check)
                              └── Consensus voter (binary verdict)
                                          │
                                          ▼
                          [MongoDB audit log] → if attack:
                                          │
                                          ▼
                            [FP-Growth pattern miner]
                                          │
                                          ▼
                  [LLM / template orchestrator → SecRule candidate]
                                          │
                                          ▼
                  [Human-in-the-loop approval in dashboard]
                                          │
                                          ▼
                  [Hot-reload back into Coraza] — loop closes
```

### Module map (11 SRS modules, all DONE)

| # | Module | What it does |
|---|---|---|
| M1 | Reverse proxy + TLS | Go proxy with self-signed certs in dev |
| M2 | Normalisation + features | URL-decode + extract 11 numeric features (length, entropy, n-gram entropy, special-char ratio, etc.) |
| M3 | Rule engine | Coraza (Go ModSecurity) + OWASP CRS v4.7.0 + Spamhaus threat-intel feed (12h hot-reload) |
| M4 | Autoencoder | Keras MLP 11→16→8→**4**→8→16→11. Trained on benign traffic. High reconstruction error = anomaly. |
| M5 | HDBSCAN | Density clustering in the 4-dim bottleneck space. Request landing in cluster -1 (outlier) = second anomaly signal. |
| M6 | Consensus | Weighted/Majority/Strict voting across CRS verdict + AE score + HDBSCAN outlier flag → final binary verdict. |
| M7 | Audit log | Every request stored in MongoDB with 90-day TTL. |
| M8 | FP-Growth miner | Frequent-itemset mining over confirmed-attack audit rows → recurring attack patterns. |
| M9 | Rule synthesis | LLM (Gemini Flash free tier, with stub fallback) turns mined patterns into draft `SecRule` text. |
| M10 | HITL rule approval | Human operator reviews drafted rules in dashboard; approved rules hot-loaded into Coraza. |
| M11 | Drift watch + model HITL | Background watcher detects feature drift, triggers retrain → operator approves new model before promotion. |

Plus: JWT auth, RBAC (4 roles), TOTP MFA, account lockout, decision
override audit, model-accuracy panel, CEF/Syslog export, sandbox-test
of candidate rules, live training-loss chart, operator-controllable
safe-mode banner. (Details: `CLAUDE.md` and `docs/architecture.md`.)

### Known honest gaps (don't hide these, defend them)

1. **TPR on CSIC dataset ≈ 27%** — the model is trained on Juice Shop
   traffic, so it underfits attacks whose *content* looks benign-shaped
   (SQL keywords in a normal-length parameter). Coraza catches those;
   the layers are complementary. See `docs/roadmap.md`.
2. **P95 latency ≈ 170 ms** vs the 150 ms target. Per-request Keras
   `predict` over a tiny batch incurs ~30 ms framework overhead.
3. **"Continuous learning"** is scheduled (cron-style), not true
   streaming. Document the constraint.

---

## Part 2 — what we're trying to publish (paper paths explained)

We want a peer-reviewed paper out of this codebase. There are two
realistic framings. **Pick one. Or combine A + B1 (recommended).**

### Path A — "systems paper"

**Claim:** *the closed loop itself is the contribution.*
Most WAFs are static (rules written once, attack landscape moves on).
We built a WAF that mines patterns from its own traffic, drafts rules
with an LLM, gets a human to approve them, and hot-loads them back —
all in production-grade containers with RBAC, MFA, audit, and
fail-safe mode. **No one paper combines all of this.**

What we'd need to add to publish:
- **A1.** Comparative TPR/FPR over time vs static-rule baseline.
- **A2.** Operator-labour metric: how many mined candidates get
  approved, time-from-attack-onset-to-rule-live.
- **A3.** Multi-app generalisation: same stack against 2-3 different
  upstreams (Juice Shop, DVWA, WebGoat).
- **A4.** Adversarial pressure test: throw obfuscated payloads at it.
- **A5.** Honest comparison vs ModSecurity-alone, AWS WAF managed
  rules, Cloudflare free tier.

**Effort:** ~2-3 weeks. **Risk:** low — the system already exists.
**Target venues:** ACSAC, RAID, DSN systems track, DIMVA.

### Path B — "ML novelty paper"

The ML layer right now is *adequate* — vanilla autoencoder + HDBSCAN +
consensus. Not a research contribution on its own. To publish on ML
specifically, we'd need a novel ML idea. **Pick ONE of these:**

- **B1. Per-shape contrastive autoencoder ⭐ recommended.** Instead of
  one global AE, train one AE per `(method, path-prefix)` combination
  (e.g. one for `POST /login`, one for `GET /products`). Plus replace
  reconstruction loss with **supervised contrastive loss** — pull
  benign requests together in embedding space, push known attacks
  apart. Genuinely under-explored for WAF. **CPU-trainable.** ~2 weeks.
- **B2. HTTP-BERT.** Small Transformer encoder (4 layers, ~5M params)
  trained MLM-style on benign HTTP. Anomaly score = perplexity of
  the request under the model. Highest paper ceiling. ~3-4 weeks.
  **Needs Colab/Kaggle free GPU.**
- **B3.** Active learning + adversarial robustness. Workshop tier.
- **B4.** Sparse-bottleneck interpretability. Workshop tier.
- **B5.** Federated learning across two LatentGuard instances. High
  novelty, high risk, hard to evaluate alone. Recommend as
  future-work, not as the paper.

### Our recommended pick: **A + B1 combined**

Systems paper (Path A) as the backbone, per-shape contrastive
autoencoder (B1) as the ML contribution inside it. Strongest defensible
story. ~3-4 weeks total. **No GPU required.**

Implementation order (full breakdown in `todo.md` → Research-paper
roadmap):
1. Adversarial-eval harness (LLM/obfuscation mutator + recall-delta
   script) — 2 days
2. Per-shape AE infrastructure (shape clustering + router) — 3 days
3. Contrastive-loss training option in `train_autoencoder.py` — 2 days
4. `bench/` eval automation (multi-week simulated attack runs,
   CSV/JSON/matplotlib output) — 3 days
5. Baselines: ModSecurity-only, CRS-only — 2 days

**~12 working days for an experimental section worth writing up.**

---

## Part 3 — what to study (the actual plan)

Now you know the project and the paper goal. This is what you must
learn to own them.

### Tier 0 — math you can't dodge (1 week)

You don't need a PhD, you need working fluency.

- **Linear algebra:** vectors, dot product, matrix multiplication,
  eigenvectors (intuition only). → 3Blue1Brown *Essence of Linear
  Algebra* (YouTube, ~3 hrs total).
- **Probability:** conditional probability, Bayes rule, expectation,
  variance, Gaussian. *Why:* anomaly scoring is fundamentally
  `P(x | benign) is low`.
- **Calculus for ML:** partial derivatives, chain rule, gradient. You
  don't derive backprop, but you must explain *why gradient descent
  works* without hand-waving.
- **Information theory:** entropy (Shannon), KL divergence,
  cross-entropy. *Why:* our 11 features include Shannon entropy and
  n-gram entropy directly.

Resource: Goodfellow *Deep Learning* book, Ch 2-3 (free online). Skim.

### Tier 1 — the techniques actually in our repo (2 weeks)

Every one of these is in code right now. You MUST be able to
whiteboard each.

#### Autoencoders (M4)
- Vanilla AE architecture: encoder → bottleneck → decoder.
- Reconstruction loss (MSE). Why MSE not cross-entropy here.
- Bottleneck dimensionality trade-off (we use 4 from 11).
- Why AEs detect anomalies: in-distribution reconstructs well, OOD
  reconstructs poorly → high error = anomaly.
- **Failure modes:** AE can learn identity if bottleneck too wide; AE
  generalises *too well* and reconstructs attacks fine if attack shape
  ≈ benign shape. (This is exactly our CSIC ~27% TPR problem — must
  own this in viva.)
- Read: Goodfellow Ch 14 (Autoencoders).

#### HDBSCAN (M5)
- Density-based clustering vs k-means (no k, finds outliers as label -1).
- Concepts: mutual reachability distance, condensed tree, cluster
  stability.
- Why HDBSCAN over DBSCAN: handles variable density.
- Why we use it: bottleneck-space clusters define "normal regions";
  request landing as outlier (-1) = second anomaly signal.
- Read: Campello et al. 2013 abstract + intro + the `hdbscan` Python
  docs "How HDBSCAN Works".

#### FP-Growth (M8)
- Frequent itemset mining: support, confidence, lift.
- FP-Growth vs Apriori (we picked it: faster, no candidate generation).
- How we map HTTP requests → itemsets: each attack-confirmed request
  becomes a transaction of `{path-prefix, method, rule-IDs, ip-/24,
  AE-high, outlier-high, body-present}`. Frequent itemsets = recurring
  attack patterns.
- Read: Han et al. 2000 FP-Growth paper, sections 1-3.

#### Multi-signal consensus (M6)
- Weighted / Majority / Strict voting schemes.
- Per-model weight sliders summing to 100.
- Decision threshold tuning + ROC curve relationship.
- Honest framing: it IS an ensemble of 3 detectors (CRS + AE +
  HDBSCAN). Read Dietterich 2000 ensemble survey (short).

#### TLS / reverse proxy fundamentals (M1)
Not ML, but you will be asked: SNI, certificate chains, why we
self-sign in dev, why a reverse proxy can decrypt + inspect.

### Tier 2 — what we NEED for the paper (2 weeks)

#### For everyone (whether we go Path A, B1, B2, or A+B1)

- **Evaluation metrics deep dive:** precision, recall, F1, FPR, TPR,
  ROC-AUC, PR-AUC, **why PR-AUC matters more than ROC-AUC on
  imbalanced data** (WAF traffic is 99%+ benign).
- **Confusion matrix discipline.** TP/FP/TN/FN definitions in the WAF
  context — what counts as "ground truth" in our 141-payload battery?
- **Statistical significance:** McNemar's test for paired classifier
  comparison (you'll need this for "B1 beats baseline AE"). Bootstrap
  confidence intervals on metrics.
- **Adversarial ML basics:** FGSM, PGD (intuition only); why
  WAF-specific adversarial = payload obfuscation (URL encoding, case
  mixing, comment injection) not pixel perturbation.

#### Only if pursuing B1 (per-shape contrastive AE — recommended)

- **Contrastive learning:** SimCLR (Chen et al. 2020), supervised
  contrastive (Khosla et al. 2020). Core idea: pull positives together,
  push negatives apart in embedding space.
- **Triplet loss vs NT-Xent loss vs SupCon loss.** Know trade-offs.
- **Why per-shape (per-(method, path-prefix)) matters:** distribution
  shift across endpoints. `/login` POST traffic distribution ≠
  `/products` GET. One model = averaged failure mode. We're proposing
  shape-routed specialists.
- **Embedding-space anomaly detection:** distance to nearest benign
  cluster centroid instead of reconstruction error.
- Read: Khosla 2020 SupCon paper + Liu et al. 2021 self-supervised
  survey.

#### Only if pursuing B2 (HTTP-BERT — needs Colab GPU)

- **Transformer architecture:** self-attention, multi-head, positional
  encoding, encoder vs decoder. → Jay Alammar "Illustrated Transformer".
- **BERT specifically:** MLM (masked language modelling), WordPiece
  tokenisation, [CLS] / [MASK] tokens. → Devlin 2018 paper.
- **Tokenisation for HTTP:** off-the-shelf tokenisers are bad for URLs
  and payloads. We'd train byte-pair encoding (BPE) on HTTP corpus, OR
  use character-level. Read Karpathy's `minbpe` repo.
- **Perplexity as anomaly score:** language model assigns low
  probability to OOD strings → high perplexity → anomaly.
- **Distillation / tiny BERTs:** TinyBERT, DistilBERT — we can't train
  BERT-base on Colab free tier; must go small.

### Tier 3 — domain knowledge (1 week, parallel with Tier 2)

A WAF paper reviewed by a security venue needs security depth.

- **OWASP Top 10 2021** — know all ten, especially A03 Injection +
  A07 ID&Auth failures.
- **OWASP CRS v4 architecture:** paranoia levels, anomaly scoring, the
  request/response inspection phases (1-5).
- **Attack classes in our 141-payload battery (19 classes):** SQLi
  (union, error, blind, time-based), XSS (reflected, stored, DOM),
  CSRF, SSRF, RCE, LFI/RFI, LDAP injection, XXE, SSTI, deserialisation,
  scanner UAs, XFF spoofing. Own each.
- **Evasion techniques:** URL encoding (single/double), HTML entity
  encoding, comment injection (`/**/`), case manipulation, NULL byte
  injection, HPP (HTTP parameter pollution), chunked encoding tricks.
- **Existing WAF research:** read 5 papers minimum
  - ModSec-AdvLearn (Demetrio et al.) — adversarial training for WAF
  - Robust-WAF / DeepWAF surveys
  - "An Anomaly-Based Web Application Firewall" (Pałka et al.)
  - HTTP2vec / Request2Vec papers
  - any recent (2023-2025) WAF + LLM paper

Find them: Google Scholar `"web application firewall" machine
learning` sorted by year. Read related-work sections of two recent
papers to map the field fast.

### Tier 4 — research craft (ongoing, ~1 week to set up)

- **How to read a paper fast:** S. Keshav's "How to Read a Paper"
  (3 pages, life-changing).
- **Reproducibility checklist:** NeurIPS / ACM checklists — our
  `bench/` harness must satisfy these.
- **Experimental hygiene:** train/val/test split, hyperparameter search
  vs test leakage, fixed random seeds, multiple runs with confidence
  intervals (not single numbers).
- **Plotting:** matplotlib basics. Publication-quality figures (label
  axes, legible at 50% size).
- **Paper structure:** abstract → intro → related work → method →
  evaluation → discussion → conclusion. Read 3 papers from our target
  venue (RAID, DIMVA, ACSAC).
- **LaTeX:** Overleaf is fine. Don't write the paper in Word.
- **Citation tooling:** Zotero or BibTeX. Track every paper from day 1.

### Tier 5 — only if we pick B2 (HTTP-BERT)

- PyTorch (we use Keras; B2 is easier in PyTorch + HuggingFace).
- HuggingFace `datasets` + `transformers` + `tokenizers`.
- Colab GPU notebook discipline: save checkpoints to Drive, never
  trust the runtime to persist.
- Mixed-precision training (fp16) — Colab T4 has limited VRAM.

---

## Part 4 — suggested 6-week schedule

| Week | Focus |
|---|---|
| 1 | Tier 0 math + Tier 1 (AE + HDBSCAN) |
| 2 | Tier 1 (FP-Growth + consensus). All repo-specific theory done. |
| 3 | Tier 2 metrics + statistical tests + Tier 3 OWASP/CRS depth |
| 4 | Tier 2 contrastive learning (B1) OR Transformers (B2). **Pick now.** |
| 5 | Tier 3 read 5 WAF papers + Tier 4 paper-craft + start `bench/` harness |
| 6 | Implementation on chosen B path; first experiments running |

After week 6 you're running baseline experiments + reading related work
in parallel. Writing starts week 8-10.

---

## Part 5 — resources, ranked

**Books (skim, don't grind):**
1. Goodfellow, Bengio, Courville — *Deep Learning* (free online).
   Ch 1-5, 14, 17.
2. Murphy — *Probabilistic Machine Learning: An Introduction*
   (free PDF). For probability + linear algebra refreshers.

**Courses:**
1. Andrew Ng *Deep Learning Specialization* — only Course 1 + 2.
2. fast.ai *Practical Deep Learning* — Lesson 1-4. Faster than Ng for
   builders.

**YouTube:**
- 3Blue1Brown — linear algebra + neural networks series.
- StatQuest (Josh Starmer) — stats + ML intuition. Excellent.
- Yannic Kilcher — paper walkthroughs.

**Papers (must-read, in order):**
1. Vincent et al. 2008 — Denoising autoencoders (foundation of M4)
2. Campello et al. 2013 — HDBSCAN
3. Han et al. 2000 — FP-Growth
4. Khosla et al. 2020 — Supervised Contrastive Learning (B1 critical)
5. Chen et al. 2020 — SimCLR (B1 context)
6. Devlin et al. 2018 — BERT (skim if Path A only)
7. Any 2-3 recent WAF-ML papers from our target venue

**Hands-on:**
- Karpathy's "Neural Networks: Zero to Hero" YouTube series. Build a
  tiny GPT from scratch. Best 10 hours for Transformer intuition.
- Re-implement the AE in `ml/training/train_autoencoder.py` from
  scratch in a notebook. If you can't, you don't understand it yet.

---

## Part 6 — self-test (do this before viva)

Can you, without notes:

- [ ] Explain LatentGuard's 3-layer pipeline end-to-end?
- [ ] Name the 11 SRS modules and what each does?
- [ ] Whiteboard the AE architecture + forward pass + loss?
- [ ] Explain why bottleneck width matters; what happens if too wide?
- [ ] Explain why HDBSCAN finds outliers but k-means doesn't?
- [ ] State support / confidence / lift definitions; which we threshold on?
- [ ] Define precision, recall, F1, FPR, TPR from a confusion matrix?
- [ ] Explain why PR-AUC > ROC-AUC for imbalanced data?
- [ ] Justify our 4-dim bottleneck (or admit it's heuristic)?
- [ ] Defend the 27% CSIC TPR honestly without flinching?
- [ ] Explain Path A vs Path B1 in two sentences each?
- [ ] Explain contrastive loss in one sentence (if pursuing B1)?
- [ ] Explain MLM + perplexity-as-anomaly (if pursuing B2)?
- [ ] Name 5 evasion techniques and what defence catches each?
- [ ] Cite 3 prior WAF-ML papers and what they got wrong / right?

If any "no" — back to that tier.

---

## Part 7 — what NOT to study (yet)

Time-wasters at this stage:
- Reinforcement learning
- Diffusion models / image generation
- LLM fine-tuning frameworks (we're calling Gemini API, not training)
- Graph neural networks
- AutoML platforms

Stay focused. Six weeks is tight.

---

## Where to look in the repo

- `CLAUDE.md` — orientation for any new contributor
- `docs/architecture.md` — full data flow + repo layout
- `docs/roadmap.md` — phase plan + honest gaps
- `docs/gotchas.md` — 42 landmines tagged by area
- `docs/verified-states.md` — what's currently working with metrics
- `todo.md` — backlog including the research-paper roadmap (Path A/B)
- `fyp-documents/` — official SRS + SDS markdown
- `ml/app/` — every Python module of the ML service
- `proxy/internal/` — every Go package of the reverse proxy
