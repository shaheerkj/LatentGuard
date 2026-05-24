# Study plan — everything to learn before presenting LatentGuard

A self-contained checklist of topics. If you can explain each line item
without notes, you can defend the project in viva or talk through it
with a stranger. Topics are grouped by area; depth needed is marked:

- ★ = working intuition (one paragraph, one diagram)
- ★★ = can implement a small version
- ★★★ = can explain trade-offs and failure modes

For paper-specific topics and research direction, see
`todo.md` → Research-paper roadmap. This file is purely *what to study*.

---

## 1. Web + networking foundations

You can't reason about a WAF without these.

- **HTTP/1.1 protocol** ★★ — request line, headers, body, methods
  (GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS), status codes (2xx/3xx/4xx/5xx
  meaning), chunked transfer-encoding, keep-alive.
- **HTTP/2 and HTTP/3** ★ — multiplexing, header compression (HPACK),
  why they complicate WAF inspection.
- **URL anatomy** ★★ — scheme, host, port, path, query string,
  fragment, percent-encoding, double-encoding, IDN/punycode.
- **TLS 1.2 / 1.3** ★★ — handshake steps, cipher suites, SNI,
  certificate chains, root CAs, why a reverse proxy must terminate TLS
  to inspect plaintext.
- **Self-signed certificates** ★ — how to generate, why browsers warn,
  when it's acceptable (dev only).
- **Reverse proxy vs forward proxy** ★★ — definitions, why a WAF is a
  reverse proxy.
- **CORS** ★ — preflight requests, headers, why misconfiguration is a
  bug class.
- **Cookies + sessions** ★★ — `HttpOnly`, `Secure`, `SameSite`, session
  fixation.

---

## 2. Web application security (OWASP)

You will be asked about every one of these attack classes.

- **OWASP Top 10 (2021)** ★★ — name all ten, give one example each.
- **SQL injection** ★★★ — union-based, error-based, boolean-blind,
  time-blind, second-order, stacked queries. Why parameterised queries
  fix it.
- **Cross-site scripting (XSS)** ★★★ — reflected, stored, DOM-based;
  why CSP helps; encoding contexts (HTML body vs attribute vs JS vs URL).
- **Cross-site request forgery (CSRF)** ★★ — token defence, SameSite
  cookies.
- **Server-side request forgery (SSRF)** ★★ — IMDS abuse, blind SSRF,
  DNS rebinding.
- **Remote code execution (RCE)** ★★ — shell injection, eval injection,
  template injection.
- **Local file inclusion / remote file inclusion (LFI / RFI)** ★★ —
  path traversal, null-byte tricks, `php://` wrappers.
- **LDAP injection** ★ — filter syntax, escape rules.
- **XML external entity (XXE)** ★★ — entity expansion, OOB exfiltration.
- **Server-side template injection (SSTI)** ★★ — Jinja2/Twig sandbox
  escapes.
- **Insecure deserialisation** ★ — Python pickle, Java/PHP gadgets.
- **HTTP parameter pollution (HPP)** ★ — duplicate parameters, parser
  inconsistencies.
- **Header-based attacks** ★ — X-Forwarded-For spoofing, Host header
  injection, request smuggling.
- **Scanner detection** ★ — typical user-agents (Nikto, Acunetix, ZAP,
  Burp Collaborator), why UA alone is weak signal.

### Evasion techniques

- URL encoding (single, double, mixed-case `%2E%2E`)
- HTML entity encoding (`&#x27;`, `&apos;`)
- Comment injection (`UNION/**/SELECT`)
- Case manipulation (`UnIoN SeLeCt`)
- NULL byte injection (`%00`)
- Unicode normalisation tricks
- Chunked encoding splits
- Whitespace alternates (`%09`, `%0a`, `+`)

---

## 3. Web Application Firewalls

- **What a WAF actually does** ★★ — request inspection point,
  decisions, modes (detection / blocking / safe).
- **Rule-based vs anomaly-based vs hybrid** ★★ — trade-offs of each.
- **ModSecurity** ★★ — directives (`SecRule`, `SecAction`,
  `SecRuleEngine`), variables (`ARGS`, `REQUEST_URI`, `REQUEST_HEADERS`),
  transformations (`t:lowercase`, `t:urlDecodeUni`), actions (`block`,
  `pass`, `drop`, `deny`), phases 1–5.
- **Coraza** ★ — Go-native ModSecurity v3 fork; engine reload API.
- **OWASP Core Rule Set (CRS) v4** ★★ — paranoia levels (1–4),
  anomaly scoring, inbound/outbound thresholds, rule numbering
  conventions (9xxxxx for CRS, custom rule bands).
- **False positives in WAFs** ★★ — why paranoia level 1 is default,
  the cost of blocking legitimate traffic.
- **Threat intelligence feeds** ★ — Spamhaus DROP/EDROP, MISP, OTX —
  what they list, refresh cadence.

---

## 4. Linear algebra (math floor)

- **Vectors and dot products** ★★ — geometric interpretation,
  cosine similarity.
- **Matrix multiplication** ★★ — dimensions, why order matters.
- **Eigenvectors and eigenvalues** ★ — intuition only; PCA depends on it.
- **Norms** ★★ — L1, L2, L∞; when to use each.

Resource: 3Blue1Brown *Essence of Linear Algebra* (YouTube series).

---

## 5. Probability + statistics

- **Random variables, expectation, variance** ★★
- **Gaussian / normal distribution** ★★ — z-scores, why so common.
- **Conditional probability + Bayes rule** ★★
- **Maximum likelihood estimation** ★ — what training a model
  actually optimises.
- **Hypothesis testing basics** ★ — p-values, type I / II errors.
- **McNemar's test** ★★ — paired classifier comparison, what we use
  to say "model A beats model B".
- **Bootstrap confidence intervals** ★★ — reporting metric ± CI
  instead of single numbers.

---

## 6. Information theory

- **Shannon entropy** ★★★ — definition, max entropy uniform, low
  entropy = predictable. Used directly in feature extraction.
- **Cross-entropy** ★★ — relation to log-likelihood, classification
  loss.
- **KL divergence** ★ — distance between distributions; appears in VAE.
- **N-gram entropy** ★★ — entropy over substrings of length n; how
  it detects unusual character sequences.

---

## 7. Calculus for ML

- **Partial derivatives + chain rule** ★★
- **Gradient + gradient descent** ★★★ — step size, why it converges
  for convex losses, why deep nets are non-convex.
- **Backpropagation intuition** ★★ — you don't need to derive it, but
  you must explain what it computes.
- **Optimisers** ★★ — SGD, Momentum, Adam — when to use which.

---

## 8. Neural networks basics

- **Perceptron, MLP, activation functions** ★★ — sigmoid, tanh, ReLU,
  LeakyReLU, why ReLU is the default.
- **Forward pass + loss + backward pass** ★★★
- **Loss functions** ★★ — MSE for regression, cross-entropy for
  classification, custom losses.
- **Regularisation** ★★ — L1, L2, dropout, early stopping, batch
  normalisation.
- **Overfitting vs underfitting** ★★★ — bias-variance trade-off,
  train/val/test split discipline.
- **Hyperparameters** ★★ — learning rate, batch size, epoch count,
  hidden width / depth — how each affects training.

---

## 9. Autoencoders (the core of M4)

- **Vanilla AE** ★★★ — encoder → bottleneck → decoder; reconstruction
  loss; why bottleneck must be narrower than input.
- **Denoising AE, sparse AE, contractive AE** ★★ — when to use each.
- **Anomaly detection with AE** ★★★ — train on benign only;
  reconstruction error threshold; why this works (and when it doesn't).
- **Failure modes** ★★★ — bottleneck too wide → learns identity;
  AE generalises too well → reconstructs attacks fine; class imbalance
  in training data.
- **Variational autoencoder (VAE)** ★ — probabilistic bottleneck,
  KL term in loss.

---

## 10. Clustering

- **K-means** ★★ — algorithm, must pick k, fails on non-globular
  clusters.
- **DBSCAN** ★★ — density-based, `eps` + `min_samples`, finds outliers.
- **HDBSCAN** ★★★ — hierarchical DBSCAN, no `eps` parameter, cluster
  stability, mutual reachability distance, condensed tree, why label
  `-1` means outlier.
- **Silhouette score** ★ — measuring cluster quality.

---

## 11. Frequent pattern mining

- **Transactions, itemsets, support, confidence, lift** ★★★ —
  definitions and how to compute by hand on a small example.
- **Apriori algorithm** ★★ — candidate generation + pruning.
- **FP-Growth** ★★★ — FP-tree construction, conditional pattern bases,
  why it beats Apriori (no candidate explosion).
- **Mapping non-transactional data to itemsets** ★★ — how categorical
  + binned numeric features become items.

---

## 12. Ensembles + consensus

- **Why ensembles work** ★★ — bias-variance reduction; uncorrelated
  errors cancel.
- **Voting schemes** ★★★ — hard voting (majority), soft voting
  (weighted probability), strict (all-must-agree).
- **Bagging vs boosting vs stacking** ★ — names and one-line
  differences.
- **Calibration** ★ — when raw model scores aren't probabilities;
  Platt scaling, isotonic regression.

---

## 13. Evaluation metrics

- **Confusion matrix** ★★★ — TP, FP, TN, FN; sketch from memory.
- **Accuracy** ★★ — why it's misleading on imbalanced data.
- **Precision, recall, F1** ★★★
- **False positive rate (FPR), true positive rate (TPR)** ★★★
- **ROC curve + AUC** ★★ — interpretation, when it's misleading.
- **Precision-recall curve + PR-AUC** ★★★ — why this matters more on
  imbalanced data (and WAF traffic is 99 %+ benign).
- **Latency metrics** ★★ — p50, p95, p99; why p95 matters more than
  mean.
- **Throughput** ★ — requests/sec, how to measure honestly.

---

## 14. Contrastive learning (only if we go ML-novelty)

- **Self-supervised vs supervised contrastive** ★★
- **SimCLR** ★ — augmentations, NT-Xent loss, batch size effects.
- **Supervised contrastive loss (SupCon)** ★★ — label-aware positives
  and negatives.
- **Triplet loss** ★ — anchor / positive / negative formulation.
- **Embedding-space anomaly detection** ★★ — distance to centroid
  instead of reconstruction error.

Reference paper: Khosla et al. 2020 *Supervised Contrastive Learning*.

---

## 15. Transformers + language modelling (only if HTTP-BERT route)

- **Self-attention** ★★★ — query/key/value, softmax, scaling.
- **Multi-head attention** ★★ — why multiple heads.
- **Positional encoding** ★★ — sinusoidal vs learned.
- **Encoder vs decoder vs encoder-decoder** ★★
- **BERT** ★★ — MLM objective, [CLS], [MASK], WordPiece tokens.
- **Tokenisation** ★★ — byte-pair encoding (BPE), why off-the-shelf
  tokenisers fail on URLs.
- **Perplexity** ★★ — language model probability; using perplexity as
  an anomaly score.
- **Distillation** ★ — TinyBERT, DistilBERT for CPU/Colab budgets.

Resources: Jay Alammar *Illustrated Transformer*; Karpathy
*Neural Networks: Zero to Hero* YouTube series; Devlin et al. 2018 BERT
paper.

---

## 16. Adversarial ML basics

- **FGSM, PGD** ★ — gradient-based pixel perturbation (image-domain).
- **Adversarial in WAF context** ★★★ — *not* pixel noise; it's payload
  obfuscation (encoding, comments, case, whitespace). Different attack
  surface.
- **Adversarial training** ★ — augmenting training data with mutated
  payloads; trade-off with benign accuracy.

---

## 17. Software stack — Python ML

- **NumPy** ★★★ — arrays, broadcasting, vectorised ops.
- **Pandas** ★★ — DataFrame, groupby, joins.
- **scikit-learn** ★★ — fit/predict API, pipelines, cross-validation.
- **Keras / TensorFlow** ★★ — Sequential vs functional API, training
  loop, callbacks, saving/loading models.
- **PyTorch** ★ — alternative to Keras; required only if going the
  Transformer route.
- **HuggingFace Transformers + datasets + tokenizers** ★ — same
  caveat.
- **mlxtend** ★ — where our FP-Growth implementation comes from.
- **hdbscan** Python package ★★ — fit, `labels_`, `outlier_scores_`.
- **FastAPI** ★★ — routes, dependency injection, OpenAPI docs.
- **pydantic** ★★ — request/response schema validation.
- **pyotp** ★ — TOTP code generation and verification.
- **bcrypt** ★ — password hashing, work factor.

---

## 18. Software stack — Go (proxy)

- **Go basics** ★★ — packages, goroutines, channels, error handling,
  context.
- **net/http** ★★ — server, handler, middleware pattern.
- **httputil.ReverseProxy** ★ — how the standard library handles
  proxying.
- **Coraza API** ★ — engine load, request inspection, reload.
- **atomic primitives** ★ — `atomic.Bool`, `atomic.Value` for shared
  state without mutexes.

---

## 19. Infrastructure

- **Docker** ★★ — image vs container, layers, Dockerfile directives,
  build cache.
- **docker-compose** ★★ — services, networks, volumes (named vs bind),
  environment, healthchecks.
- **MongoDB** ★★ — collections, documents, indexes, TTL indexes,
  aggregation pipeline basics.
- **Redis** ★ — when it's useful (caching, rate limiting); we don't
  use it but you'll be asked why not.
- **JWT** ★★★ — header.payload.signature, HS256 vs RS256, expiry,
  claims (iss, sub, exp, role).
- **TOTP** ★★ — RFC 6238, shared secret, 30-second window, drift
  tolerance.
- **RBAC** ★★ — roles, permissions, role hierarchies, principle of
  least privilege.
- **CEF (Common Event Format)** ★ — ArcSight format, syslog facility /
  severity.

---

## 20. LLM API integration

- **Prompting basics** ★★ — system vs user message, few-shot, JSON
  mode.
- **Rate limits + retries** ★ — exponential back-off.
- **Free-tier providers** ★ — Gemini Flash, OpenRouter free models,
  Groq.
- **Security risks of LLM-in-the-loop** ★★ — prompt injection,
  jailbreaks, hallucinated output that becomes a SecRule.

---

## 21. Research craft

- **How to read a paper fast** ★★ — three-pass method (Keshav).
- **Reproducibility** ★★ — fixed seeds, environment lock files,
  multiple runs.
- **Train/val/test discipline** ★★★ — never tune on test, no leakage.
- **Plotting** ★★ — matplotlib, label axes, units, legible at 50 %
  size.
- **LaTeX** ★ — Overleaf; figures, tables, citations, algorithm
  environment.
- **Reference management** ★ — Zotero or BibTeX from day one.

---

## 22. Suggested order

| Week | Focus |
|---|---|
| 1 | §1 web + §2 OWASP + §3 WAF concepts |
| 2 | §4–§7 math floor (linear algebra, prob, info theory, calc) |
| 3 | §8 NN basics + §9 autoencoders + §10 clustering |
| 4 | §11 FP-Growth + §12 ensembles + §13 metrics |
| 5 | §17–§19 software stack + §20 LLM + §21 research craft |
| 6 | §14 contrastive OR §15 Transformers (whichever paper path) + §16 adversarial |

---

## 23. Self-test (do this before viva)

If you can't answer any of these without notes, go back to that section.

- [ ] Walk through what happens to an HTTP request from client to
      response, naming every component it passes through.
- [ ] Define TLS handshake steps and explain SNI.
- [ ] Name all 10 OWASP Top 10 categories with one example each.
- [ ] Write a SQL injection payload that bypasses a naive `'`-strip filter.
- [ ] Explain a `SecRule` line and what each token means.
- [ ] Define Shannon entropy and compute it on a 4-character string.
- [ ] Whiteboard an autoencoder, the loss, and one failure mode.
- [ ] Explain HDBSCAN in three sentences without saying "DBSCAN".
- [ ] Define support, confidence, lift; compute them on a 5-transaction
      example.
- [ ] Sketch a confusion matrix and derive precision, recall, F1, FPR.
- [ ] State when PR-AUC matters more than ROC-AUC and why.
- [ ] Explain why JWT signatures matter and what HS256 means.
- [ ] Describe TOTP in three sentences.
- [ ] Explain contrastive loss in one sentence (if pursuing it).
- [ ] Explain MLM + perplexity-as-anomaly (if pursuing Transformer path).
- [ ] Describe McNemar's test and when to use it.

---

## 24. Resources, ranked

**Books (skim, don't grind):**
1. Goodfellow, Bengio, Courville — *Deep Learning* (free online).
   Chapters 1–5, 14, 17.
2. Murphy — *Probabilistic Machine Learning: An Introduction*
   (free PDF) for probability + linear algebra refreshers.
3. Stuttard & Pinto — *The Web Application Hacker's Handbook* (2nd
   ed.) for attack-class depth.

**Courses:**
1. Andrew Ng — *Deep Learning Specialization*, Courses 1 + 2 only.
2. fast.ai — *Practical Deep Learning*, Lessons 1–4.
3. PortSwigger Web Security Academy (free, hands-on) for OWASP work.

**YouTube:**
- 3Blue1Brown — linear algebra + neural networks.
- StatQuest (Josh Starmer) — stats + ML intuition.
- Yannic Kilcher — paper walkthroughs.
- Andrej Karpathy — *Neural Networks: Zero to Hero*.

**Papers (in suggested reading order):**
1. Vincent et al. 2008 — Denoising Autoencoders.
2. Campello et al. 2013 — HDBSCAN.
3. Han et al. 2000 — FP-Growth.
4. Dietterich 2000 — Ensemble Methods (short survey).
5. Khosla et al. 2020 — Supervised Contrastive Learning.
6. Chen et al. 2020 — SimCLR.
7. Devlin et al. 2018 — BERT.
8. Two recent WAF + ML papers from a target venue.
