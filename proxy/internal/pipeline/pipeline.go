// Package pipeline composes Coraza inspection, ML scoring, the local decision
// reducer, and the Mongo audit writer into the single HTTP handler the proxy
// installs at "/". Extracted from cmd/proxy/main.go so it can be exercised by
// integration tests without spinning up the binary.
package pipeline

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/shaheerkj/latentguard/proxy/internal/client"
	"github.com/shaheerkj/latentguard/proxy/internal/coraza"
	"github.com/shaheerkj/latentguard/proxy/internal/decision"
	"github.com/shaheerkj/latentguard/proxy/internal/normalizer"
	"github.com/shaheerkj/latentguard/proxy/internal/storage"
)

const maxBodyBytes = 1 << 20 // 1 MiB cap to keep memory bounded

// SafeMode is the goroutine-safe flag flipped by the heartbeat loop.
type SafeMode struct{ v atomic.Bool }

func (s *SafeMode) Get() bool  { return s.v.Load() }
func (s *SafeMode) Set(b bool) { s.v.Store(b) }

// Handler builds the proxy's main HTTP handler.
//
//   - waf:     Coraza inspector (M3 enforcement)
//   - mlc:     scoring client to the FastAPI service (M4-M6 hosted there)
//   - store:   Mongo audit writer (M7); may be nil (logging is best-effort)
//   - safe:    safe-mode flag, toggled by a heartbeat goroutine on ML failure
//   - upstream: the protected app
func Handler(
	waf *coraza.Engine,
	mlc *client.MLClient,
	store *storage.Store,
	safe *SafeMode,
	upstream http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		requestID := newRequestID()

		body := readCappedBody(r)
		// Restore the body for the upstream proxy to re-read.
		r.Body = io.NopCloser(bytes.NewReader(body))

		norm := normalizer.Normalize(r, body)
		insp := waf.Inspect(r, body)
		corazaBlocked := insp.Interruption != nil

		var verdict decision.Verdict
		var mlAction string
		var mlScore float64
		var mlAnomaly float64
		var mlOutlier float64
		// Use AttackMaxSeverity, not MaxSeverity. CRS init/scoring/correlation
		// rules fire on every request; counting them inflates rule_score to
		// ~0.8 on benign traffic and trips the consensus engine into blocks.
		// Belt-and-suspenders: if no attack rules matched at all, force the
		// rule_score to 0 so a stray unset-severity match can't bubble up.
		var ruleScore float64
		if len(insp.AttackMatchedRuleIDs) > 0 {
			ruleScore = severityToFloat(insp.AttackMaxSeverity)
		}

		ruleReasons := []string{}
		if len(insp.MatchedRuleIDs) > 0 {
			ruleReasons = append(ruleReasons, "Coraza matched rule IDs: "+joinInts(insp.MatchedRuleIDs))
		}

		switch {
		case safe.Get():
			verdict = decision.FromCorazaOnly(corazaBlocked, insp.AttackMaxSeverity, true, append(ruleReasons, "ML in safe mode"))
		case corazaBlocked:
			verdict = decision.FromCorazaOnly(corazaBlocked, insp.AttackMaxSeverity, false, ruleReasons)
		default:
			// MLClient already imposes an http.Client.Timeout (ML_TIMEOUT_MS env);
			// no additional context deadline here. A double-budget would just
			// truncate the call early and trigger spurious safe-mode flips.
			ctx, cancel := context.WithCancel(r.Context())
			scoreReq := client.ScoreRequest{
				RequestID:      requestID,
				Method:         r.Method,
				Path:           r.URL.Path,
				CanonicalPath:  norm.CanonicalPath,
				CanonicalQuery: norm.CanonicalQuery,
				CanonicalBody:  norm.CanonicalBody,
				Features:       norm.Features,
				RuleScore:      ruleScore,
				RuleMatched:    intsToStrings(insp.MatchedRuleIDs),
			}
			resp, err := mlc.Score(ctx, scoreReq)
			cancel()
			if err != nil {
				log.Printf("ml: score call failed: %v", err)
				safe.Set(true)
				verdict = decision.FromCorazaOnly(false, insp.AttackMaxSeverity, true, append(ruleReasons, "ML call failed: "+err.Error()))
			} else {
				mlAction = resp.Action
				mlScore = resp.Score
				mlAnomaly = resp.AnomalyScore
				mlOutlier = resp.OutlierScore
				verdict = decision.FromML(corazaBlocked, insp.AttackMaxSeverity, resp.Action, resp.Score, append(ruleReasons, resp.Reasons...))
			}
		}

		audit := storage.AuditRecord{
			RequestID:      requestID,
			Timestamp:      started.UTC(),
			SourceIP:       sourceIP(r),
			Method:         r.Method,
			Path:           r.URL.Path,
			CanonicalPath:  norm.CanonicalPath,
			CanonicalQuery: norm.CanonicalQuery,
			CanonicalBody:  norm.CanonicalBody,
			Headers:        flattenHeaders(r.Header),
			Features:       featuresToMap(norm.Features),
			RuleAction:     ruleActionLabel(corazaBlocked),
			RuleHits:       insp.MatchedRuleIDs,
			MLAction:       mlAction,
			MLScore:        mlScore,
			MLAnomalyScore: mlAnomaly,
			MLOutlierScore: mlOutlier,
			RuleScore:      ruleScore,
			FinalAction:    verdict.Action,
			FallbackUsed:   verdict.FallbackUsed,
			Reasons:        verdict.Reasons,
			LatencyMS:      time.Since(started).Milliseconds(),
		}
		go store.Append(context.Background(), audit)

		w.Header().Set("X-LatentGuard-Request-ID", requestID)
		if verdict.Action == decision.ActionBlock {
			http.Error(w, "blocked by LatentGuard", http.StatusForbidden)
			return
		}
		upstream.ServeHTTP(w, r)
	})
}

// Heartbeat probes the ML service every interval; flips safe-mode on failure
// and clears it as soon as a probe succeeds (SRS REL-2).
func Heartbeat(mlc *client.MLClient, safe *SafeMode, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		ok := mlc.Healthy(ctx)
		cancel()
		if !ok && !safe.Get() {
			log.Println("heartbeat: ML unreachable, entering safe mode")
			safe.Set(true)
		} else if ok && safe.Get() {
			log.Println("heartbeat: ML healthy, leaving safe mode")
			safe.Set(false)
		}
	}
}

// ---------- helpers ----------

func readCappedBody(r *http.Request) []byte {
	if r.Body == nil {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		log.Printf("body read error: %v", err)
		return nil
	}
	_ = r.Body.Close()
	return body
}

func newRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b)
}

func sourceIP(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		if i := strings.Index(v, ","); i > 0 {
			return strings.TrimSpace(v[:i])
		}
		return strings.TrimSpace(v)
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > -1 {
		host = host[:i]
	}
	return host
}

func flattenHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, vs := range h {
		out[strings.ToLower(k)] = strings.Join(vs, ",")
	}
	return out
}

func featuresToMap(f normalizer.Features) map[string]interface{} {
	return map[string]interface{}{
		"length":          f.Length,
		"entropy":         f.Entropy,
		"token_count":     f.TokenCount,
		"special_ratio":   f.SpecialRatio,
		"digit_ratio":     f.DigitRatio,
		"uppercase_ratio": f.UppercaseRatio,
		"method_is_post":  f.MethodIsPost,
	}
}

func ruleActionLabel(blocked bool) string {
	if blocked {
		return "block"
	}
	return "allow"
}

// severityToFloat converts a syslog severity (0=Emergency, 7=Debug) to a
// [0, 1] score where 1.0 means "most severe". The previous version had this
// inverted -- it treated NOTICE (5) as 1.0 and CRITICAL (2) as 0.4, so CRS
// init rules (NOTICE) outscored real attack rules.
func severityToFloat(sev int) float64 {
	if sev <= 0 {
		return 1.0
	}
	if sev >= 7 {
		return 0.0
	}
	return 1.0 - float64(sev)/7.0
}

func intsToStrings(xs []int) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = strconv.Itoa(x)
	}
	return out
}

func joinInts(xs []int) string {
	return strings.Join(intsToStrings(xs), ",")
}
