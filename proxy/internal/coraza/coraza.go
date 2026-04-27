// Package coraza wraps Coraza v3 with a thin Inspect API. Enforcement
// (writing 403, audit, etc.) is owned by the main pipeline, not by this
// package — that keeps the WAF a pure analyzer the rest of the system
// can compose with the ML scorer and the consensus engine.
package coraza

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	corazaengine "github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

// Engine wraps a Coraza WAF instance.
type Engine struct {
	waf corazaengine.WAF
}

// InspectionResult is the analyser output from one request.
type InspectionResult struct {
	// Interruption is non-nil when at least one rule called a disruptive
	// action (deny/drop/redirect). The pipeline decides whether to honour it.
	Interruption *types.Interruption

	// MatchedRuleIDs lists every rule that fired for this request, regardless
	// of severity. Used for audit logging.
	MatchedRuleIDs []int

	// MaxSeverity is the highest severity reported across all matched rules,
	// in syslog convention (0=Emergency, 7=Debug). Lower int = more severe.
	// Includes CRS init/scoring rules so it fires on every request -- prefer
	// AttackMaxSeverity for consensus scoring.
	MaxSeverity int

	// AttackMatchedRuleIDs is MatchedRuleIDs filtered down to "real" attack
	// rules: CRS init (900000-901999), anomaly evaluation (949000-949999), and
	// correlation/scoring (980000-989999) are excluded because they fire on
	// every request regardless of payload.
	AttackMatchedRuleIDs []int

	// AttackMaxSeverity is the syslog severity over AttackMatchedRuleIDs only.
	// Defaults to 7 (Debug, least severe) when no attack rules matched, so the
	// consensus rule_score collapses to ~0 for clean traffic.
	AttackMaxSeverity int
}

// isCRSScaffoldRuleID returns true for CRS rule IDs that fire as part of
// initialization, anomaly accumulation, or correlation -- not real attack
// detections. Filtering these out of consensus scoring stops every benign
// request from carrying a baseline rule signal.
//
// CRS ID conventions used here:
//   - 900000-901999: top-level initialization
//   - 949000-949999: anomaly evaluation / decision
//   - 980000-989999: correlation / score reporting
//   - within each category (911xxx..944xxx), the xxx000-xxx099 suffix range
//     is per-category setup (e.g. 941013 = "Set XSS Score"), the xxx100+
//     range is actual detection. Our baseline rules at 1000000+ are
//     unaffected since the modulo check is scoped to CRS' 9xxxxx range.
func isCRSScaffoldRuleID(id int) bool {
	switch {
	case id >= 900000 && id < 902000:
		return true
	case id >= 949000 && id < 950000:
		return true
	case id >= 980000 && id < 990000:
		return true
	case id >= 900000 && id < 1000000 && id%1000 < 100:
		return true
	}
	return false
}

// New builds an Engine, loading every *.conf file under rulesDir. A missing or
// empty directory is allowed and logs a warning.
func New(rulesDir string) (*Engine, error) {
	cfg := corazaengine.NewWAFConfig().
		WithDirectives("SecRuleEngine On").
		WithDirectives("SecRequestBodyAccess On").
		WithDirectives("SecResponseBodyAccess Off")

	files, err := loadRuleFiles(rulesDir)
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		// Use WithDirectivesFromFile so Coraza resolves relative paths in
		// includes and @pmFromFile/@ipMatchFromFile operators against the
		// rule file's own directory (CRS rules reference *.data files this way).
		cfg = cfg.WithDirectivesFromFile(f)
		log.Printf("coraza: loaded rule file %s", f)
	}

	waf, err := corazaengine.NewWAF(cfg)
	if err != nil {
		return nil, fmt.Errorf("coraza waf init: %w", err)
	}
	return &Engine{waf: waf}, nil
}

func loadRuleFiles(dir string) ([]string, error) {
	if dir == "" {
		return nil, nil
	}
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("coraza: rules dir %s missing, running with no rules", dir)
			return nil, nil
		}
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("rules path %s is not a directory", dir)
	}

	var files []string
	walkErr := filepath.Walk(dir, func(path string, fi os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if fi.IsDir() {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(fi.Name()), ".conf") {
			files = append(files, path)
		}
		return nil
	})
	return files, walkErr
}

// Inspect runs the request through Coraza's request-headers and request-body
// phases. Body is supplied pre-buffered so it can be reused by callers.
func (e *Engine) Inspect(r *http.Request, body []byte) InspectionResult {
	tx := e.waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		if err := tx.Close(); err != nil {
			log.Printf("coraza: tx close: %v", err)
		}
	}()

	clientIP, clientPort := splitHostPort(r.RemoteAddr)
	tx.ProcessConnection(clientIP, clientPort, "", 0)
	tx.ProcessURI(r.URL.String(), r.Method, r.Proto)
	for k, vs := range r.Header {
		for _, v := range vs {
			tx.AddRequestHeader(k, v)
		}
	}

	result := InspectionResult{}

	if it := tx.ProcessRequestHeaders(); it != nil {
		result.Interruption = it
	}

	if len(body) > 0 {
		if _, _, writeErr := tx.WriteRequestBody(body); writeErr != nil {
			log.Printf("coraza: write body: %v", writeErr)
		}
	}

	if it, err := tx.ProcessRequestBody(); err != nil {
		log.Printf("coraza: process body: %v", err)
	} else if it != nil && result.Interruption == nil {
		result.Interruption = it
	}

	// Default to 7 (Debug) so "no rules matched" means lowest severity, not
	// most severe. Same logic for AttackMaxSeverity.
	result.MaxSeverity = 7
	result.AttackMaxSeverity = 7
	sawAny := false
	sawAttack := false
	for _, mr := range tx.MatchedRules() {
		rule := mr.Rule()
		id := rule.ID()
		sev := int(rule.Severity())
		result.MatchedRuleIDs = append(result.MatchedRuleIDs, id)
		if !sawAny || sev < result.MaxSeverity {
			result.MaxSeverity = sev
			sawAny = true
		}
		if !isCRSScaffoldRuleID(id) {
			result.AttackMatchedRuleIDs = append(result.AttackMatchedRuleIDs, id)
			if !sawAttack || sev < result.AttackMaxSeverity {
				result.AttackMaxSeverity = sev
				sawAttack = true
			}
		}
	}
	if !sawAny {
		result.MaxSeverity = 7
	}
	if !sawAttack {
		result.AttackMaxSeverity = 7
	}

	return result
}

func splitHostPort(addr string) (string, int) {
	host := addr
	port := 0
	if i := strings.LastIndex(addr, ":"); i > -1 {
		host = addr[:i]
		var p int
		fmt.Sscanf(addr[i+1:], "%d", &p)
		port = p
	}
	return host, port
}
