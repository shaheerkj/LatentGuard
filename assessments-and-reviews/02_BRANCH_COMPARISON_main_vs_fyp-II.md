# Branch Comparison: `main` vs `fyp-II`

## Overview

This document compares the two active branches of the LatentGuard project to help you decide which is best for submission and when to integrate post-submission improvements.

**Summary:** The `fyp-II` branch is **19 commits ahead** of `main`, containing Phase D advanced features including M11 completion, real LLM integration, MFA/RBAC security, and various operational improvements. However, these advances have not been re-verified as a complete integrated suite since the main merge.

This assessment covers:

1. **Branch Positioning** — Which branch is ahead, common ancestor, timeline
2. **Feature Breakdown** — What's in fyp-II that's not in main (19 commits)
3. **Module Completion Delta** — How module status changed between branches
4. **Code Quality** — Risk assessment for merging fyp-II improvements
5. **Integration Strategy** — Three options (safe, ambitious, pragmatic)
6. **Merge Conflict Prediction** — What to watch for

**Key Finding:** ✅ **`main` is safe for submission; `fyp-II` is ambitious but unverified.** Choose based on risk tolerance and time available.

---

# Detailed Comparison

## Quick Summary

| Metric | Value |
|--------|-------|
| **Common ancestor** | `937dc72` (docs: rewrite top-level README) |
| **main HEAD** | `4ca4dcb` (Merge PR #3 from fyp-II) |
| **fyp-II HEAD** | `8116aa4` (CLAUDE.md: handoff notes for next session) |
| **Commits in fyp-II NOT in main** | **19 commits** ✅ AHEAD |
| **Commits in main NOT in fyp-II** | 0 commits |
| **Merge status** | PR #3 merged main into fyp-II ancestor; fyp-II kept developing |
| **Branch stability** | main = verified; fyp-II = experimental |

---

## 19 Commits in `fyp-II` Ahead of `main`

### Phase D — Advanced Features (Post-Submission Work)

#### 1. **M11 Full: Auto-Retrain + HITL Promotion Gate** (commit `0429824`)
```
high-5: auto-retrain on drift + HITL promotion gate (M11 full)
```
- Completes M11 (Continuous Learning) — was marked PARTIAL on main
- Auto-retrain trigger now active (not just drift detection)
- HITL approval flow gates promotion (rule sandbox testing)
- **Impact:** M11 moves from PARTIAL → COMPLETE ✅

#### 2. **Gemini Flash LLM Integration** (commit `e7e2378`)
```
#1 wire Gemini Flash provider for M9 rule synthesis
```
- Real LLM provider (Google Gemini Flash) wired into M9
- Not just stubs anymore — active AI rule generation
- Replaces the template-only orchestrator
- **Impact:** M9 no longer requires OPENAI_API_KEY or ANTHROPIC_API_KEY workaround ✅

#### 3. **Candidate Rule Sandboxing** (commit `ad2bf1a`)
```
#2 sandbox-test a candidate rule before promotion (FR5.5)
```
- Test generated rules on live traffic before deploying to Coraza
- Reduces risk of bad rules breaking the WAF
- **Impact:** M10 approval now includes validation step ✅

#### 4. **Live Training-Loss Chart** (commit `a8a13a3`)
```
#4 live training-loss chart (FR7.4)
```
- Dashboard shows real-time training loss during retraining
- `/api/models/training-status` endpoint
- **Impact:** Operator visibility into model improvement ✅

#### 5. **MFA + Account Lockout** (commit `9ff3845`)
```
#3 MFA + account lockout + brute-force watch (SEC-1, SEC-4, SEC-10)
```
- Multi-factor authentication on dashboard login
- Brute-force protection (account lockout after N failures)
- **Impact:** Security hardened for production ✅

#### 6. **Decision Override + Audit** (commit `6a2ae89`)
```
#5 decision override + reason audit (FR4.5)
```
- Operator can manually override a block/allow decision
- Full audit trail of who overrode what, when, why
- **Impact:** HITL on individual requests (complementary to rule-level M10) ✅

#### 7. **RBAC: Four Roles + User Management** (commit `8782d2c`)
```
RBAC: four roles + user management + role-aware UI
```
- Admin / Auditor / ML-Engineer / Analyst
- Role-based access control on all dashboard endpoints
- User management panel
- **Impact:** Production-grade multi-tenant operator interface ✅

#### 8. **n-Gram Features for Autoencoder** (commit `d0b5db8`)
```
ml: char n-gram features (3 + 4 grams) on AE input
```
- Extended AE input from 7 numeric features → 7 + n-gram analysis
- Better payload similarity detection
- **Impact:** M4 (autoencoder) improved discrimination ✅

#### 9. **Quick Wins Bundle** (commit `efe52c7`)
```
quick wins: TTL on audit log + pin CRS version + copy-as-curl
```
- Audit log TTL (auto-expire old records to save storage)
- CRS version pinning (prevent surprise rule changes)
- Copy-as-curl on dashboard requests
- **Impact:** Operational polish ✅

#### 10–13. **High-Value Features (high-1 to high-4)**

| Commit | Feature | Impact |
|--------|---------|--------|
| `8560dfe` | Operator-controllable safe-mode + global banner | Force proxy into rule-only (ML bypass) when needed |
| `6c6ee9c` | Model accuracy panel + topbar pill | Real-time AE/HDBSCAN metric display |
| `592d967` | SIEM export (CEF format over syslog) | Compliance: send audit logs to external SIEM |
| `7d8890d` | OpenAPI / Swagger polish | Formal API documentation + interactive testing |

#### 14. **Dashboard Topbar Refactor** (commit `751772e`)
```
dashboard: compact topbar (health rollup + user chip) + dramatic role-visible UI
```
- Condensed topbar (better real-estate for main content)
- User chip with role indicator
- Role-specific UI elements (analyst sees fewer controls than admin)
- **Impact:** UX polish for multi-role ops ✅

#### 15–19. **Documentation & Housekeeping**

| Commit | Change | Purpose |
|--------|--------|---------|
| `687be70` | Update CLAUDE.md + docs/ | Reflect M11 completion |
| `5f76a47` | Trim stale rule, update gotcha count | Clean up version 1 artifacts |
| `2c1855f` | Research-paper roadmap (todo.md) | Path A (systems) vs Path B (ML novelty) |
| `f6c4985` | End-to-end study plan for AI work | Learning path for future phases |
| `f2fddef`, `eb7f413` | Study plan fixes | Refinements |
| `8116aa4` | Handoff notes for next session | Session closure documentation |

---

## Module Completion Delta

### Status Comparison

| Module | main | fyp-II | Delta |
|--------|------|--------|-------|
| **M1-M3** (Detection) | ✅ DONE | ✅ DONE | — |
| **M4-M6** (ML Scoring) | ✅ DONE | ✅ DONE + n-grams | Enhanced |
| **M7** (Audit Log) | ✅ DONE | ✅ DONE + TTL | Enhanced |
| **M8** (Mining) | ✅ DONE | ✅ DONE | — |
| **M9** (Rule Gen) | ✅ DONE (stub) | ✅ DONE + Gemini | **Real LLM** |
| **M10** (HITL) | ✅ DONE | ✅ DONE + Sandbox | **Validation** |
| **M11** (Drift Learn) | ⚠️ PARTIAL | ✅ DONE | **Complete** |
| **Security** | JWT only | JWT + MFA + RBAC | **Hardened** |
| **Dashboard** | Standard | Role-aware + Polish | **Enhanced** |

### Key Upgrades in fyp-II

1. **M11 moves from PARTIAL → COMPLETE** — biggest change
   - Auto-retrain trigger active (not just detection)
   - Scheduled learning gates HITL promotion
   
2. **Real LLM (M9)** instead of stub template
   - Google Gemini Flash wired up
   - Better rule synthesis quality (theory)

3. **Production security** (MFA, RBAC, brute-force)
   - Not just JWT
   - Multi-role operator dashboard

4. **Better ML features** (n-gram analysis on autoencoder input)
   - Improved anomaly discrimination
   - May improve TPR (not re-verified)

---

## Code Quality & Risk Assessment

### What's Tested

**main branch:**
- ✅ Unit tests pass (Go + Python)
- ✅ Red-team battery verified: 83.5% TPR, 0% FPR
- ✅ End-to-end integration tested
- ✅ Latency verified: p95 ~140 ms

**fyp-II branch:**
- ✅ Commits appear well-structured (commit messages clear)
- ✅ No obvious breaking changes (additive features)
- ❓ NOT re-verified as a complete integrated suite
- ❓ Red-team battery *not* re-run against fyp-II
- ❓ Gemini LLM integration not tested with live traffic
- ❓ MFA/RBAC flows not integration-tested

### Merge Conflict Risk

**Expected if you merge fyp-II → main:**
- ✅ **Low risk** — both branches evolved off same clean ancestor
- Most changes are additive (new features, no destructive refactors)
- May have minor conflicts in:
  - `docs/CLAUDE.md` (handoff notes in fyp-II vs main frozen)
  - `docs/roadmap.md` (FYP-II beyond main)
  - `ml/app/models.py` (n-gram features in fyp-II vs main's 7 features)

**Recommended merge strategy:**
```bash
git checkout main
git merge origin/fyp-II --no-ff  # explicit merge commit (easy to revert if needed)
# resolve any doc/feature conflicts
# run full test suite before committing
git commit -m "merge: integrate fyp-II Phase D features (M11 complete + Gemini + MFA)"
```

---

## Integration Decision Matrix

### Option A: Stay on `main` (Conservative, Low Risk) ✅ RECOMMENDED

**✅ Pros:**
- Proven, tested, documented
- M1–M10 fully verified + M11 partial is sufficient for submission
- Docker rebuild takes ~1 hour, ready to demo within hours
- Zero regression risk
- Safe fallback if anything goes wrong

**❌ Cons:**
- Miss the polish (MFA, RBAC, Gemini real LLM, improved AE)
- M11 not complete (auto-trigger deferred)
- Can't say "all 11 modules done" in viva

**When to choose:** 
- Short timeline (< 2 days to submission)
- Conservative strategy preferred
- Viva demo is coming up soon

---

### Option B: Merge fyp-II into main (Ambitious)

**✅ Pros:**
- All 11/11 modules truly complete
- Production-grade security (MFA, RBAC, brute-force)
- Real LLM not template-only (better rule synthesis)
- Extra validation before deploying rules (sandboxing)
- More impressive viva demo

**❌ Cons:**
- 19 new commits not individually verified as a suite
- Risk of regression in the merge
- Potential for Gemini API key issues at demo time
- More time needed to test before submission
- More complex to debug if something breaks

**When to choose:**
- Plenty of time (3+ days to submission)
- Confidence in your testing
- Want to showcase complete M11 + real AI

**Estimated effort:**
- Merge & conflict resolution: 30 min
- Full test suite (unit + integration + red-team): 1–2 hours
- Fix any regressions: 1–3 hours (unknown unknowns)
- **Total: 2–4 hours**

---

### Option C: Hybrid Approach (Pragmatic) ⭐ RECOMMENDED

1. Keep `main` as-is for safe submission baseline
2. Checkout `fyp-II` locally, rebuild & test key features:
   ```bash
   git checkout origin/fyp-II
   docker compose -f infra/docker-compose.yml up -d --build
   sleep 30
   python attacks/run_attacks.py --proxy http://127.0.0.1:8080
   # Verify 83.5% TPR not regressed (n-gram features should help)
   ```
3. If tests pass:
   - `git cherry-pick` selective commits to main (e.g., n-gram features, RBAC)
   - OR full merge if you trust it
   - Re-run tests on merged version
4. If tests fail:
   - Revert to main
   - Frame fyp-II as "post-submission improvements" in viva

**Pros:**
- Low risk (main always safe)
- Selective integration (only take what passes testing)
- Best of both worlds (submit safe + demo advanced)

**Cons:**
- Requires careful cherry-picking (watch for dependencies)
- Most commits are interdependent (full merge easier than selective)

**Estimated effort:**
- Test fyp-II locally: 1–2 hours
- Decide & integrate: 30 min
- **Total: 1.5–2.5 hours**

---

## Recommendations

### Timeline Decision Tree

```
IF (submission is < 24 hours away)
  → USE main (safest, fastest)
  → Point out fyp-II on remote as "live improvements"
  
ELSE IF (submission is 1–3 days away AND you're confident in testing)
  → USE Option C (Hybrid)
  → Test fyp-II locally
  → Cherry-pick or merge what passes
  
ELSE IF (submission is 3+ days away AND you want maximum features)
  → USE Option B (Merge fyp-II)
  → Allow time for regressions to surface
  → Fix any issues before final commit
  
OTHERWISE
  → USE main (default safe choice)
```

### Pre-Viva Checklist (Regardless of Branch Choice)

```bash
# On your chosen branch (main or merged fyp-II):

# 1. Rebuild everything
docker compose -f infra/docker-compose.yml up -d --build
sleep 30

# 2. Verify benign traffic (0% FPR)
curl http://127.0.0.1:8080/
# expect: 200 or 302
curl http://127.0.0.1:8080/login
# expect: 200/302 (not 403)

# 3. Verify attack detection (83.5% TPR baseline)
python attacks/run_attacks.py --proxy http://127.0.0.1:8080 --sleep-ms 3
# expect: ~106/127 detected
# If on fyp-II + n-grams: may be higher (not verified)

# 4. Dashboard walkthrough
curl -s http://localhost:3000/
# Open in browser, login, check:
# - KPI tiles (Total, Blocked, Block rate, P95 latency)
# - Request log (filters work)
# - Threat intel status (Spamhaus CIDRs loaded)
# - Rules tab (mining + approval UI present)

# 5. Verify threat-intel still working
curl -s http://127.0.0.1:8080/__threatintel | python -m json.tool
# expect: enabled=true, entry_count >= 1500

# 6. Verify Coraza rules load (M3)
docker logs latentguard-proxy 2>&1 | grep -i "rule"
# expect: "Loaded N rules" or similar

# 7. (Optional) Verify ML scoring active
curl -s http://127.0.0.1:8000/healthz | python -m json.tool
# expect: status=ok, version
```

---

## Honest Gaps / Known Issues

### On both `main` and `fyp-II`:

1. **M11 auto-trigger on main:** Only detection, not response
   - Manual retrain works fine
   - Sufficient for demo

2. **Keras cold-start latency:** First request after ML boot pays ~2s penalty
   - Warmup on startup mitigates this
   - Acceptable for prototype

3. **No n-grams on main:** Only 7 numeric features
   - 83.5% TPR already decent
   - fyp-II adds n-grams (theory: better TPR, unverified)

### Specific to fyp-II (not yet verified):

1. **Gemini Flash integration:** Works in development?
   - Needs API key (Google Cloud free tier)
   - May have rate limits
   - Stub fallback still works

2. **MFA flow:** Implemented but untested in integration
   - Could have UX bugs
   - Token refresh logic might have edge cases

3. **Rule sandboxing:** Test rules before deploy
   - May introduce latency (testing on live traffic)
   - Could catch bad rules or false positives

---

## Conclusion

| Question | Answer |
|----------|--------|
| **Which branch is ahead?** | **fyp-II by 19 commits** ✅ |
| **Is main stable enough for submission?** | **Yes — M1–M10 complete, M11 partial but sufficient** ✅ |
| **Is fyp-II production-ready?** | **Likely yes, but unverified as a whole since merge** ⚠️ |
| **Recommend submission on which?** | **main** (safe baseline); **test fyp-II** (impressive bonus) |
| **Time to decide?** | **Now — 2 hours to test fyp-II if you want to merge** |
| **Time to incorporate fyp-II?** | **2–4 hours** (test + selective cherry-pick or full merge) |

---

### My Recommendation

**Use Option C (Hybrid):**
1. Your main code is safe on `main` — confirmed production-ready
2. Test `fyp-II` locally for 1–2 hours to verify nothing broke
3. If `fyp-II` tests pass: merge & deploy, impress the viva committee with 11/11 modules complete + real LLM
4. If `fyp-II` tests fail: stick with `main`, frame fyp-II as "live development branch"

This way you get:
- ✅ Safety net (main always works)
- ✅ Ambition (fyp-II's features if solid)
- ✅ Pragmatism (fallback if needed)
- ✅ Optionality (decide after testing, not before)

---

*Branch comparison by Claude Code, Sept 1, 2026. Commit hashes and dates verified against origin/main and origin/fyp-II.*
