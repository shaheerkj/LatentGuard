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

	// MaxSeverity is the highest severity score seen (0..5). Used by the
	// consensus engine as `rule_score` once it's normalised to [0,1].
	MaxSeverity int
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

	for _, mr := range tx.MatchedRules() {
		rule := mr.Rule()
		result.MatchedRuleIDs = append(result.MatchedRuleIDs, rule.ID())
		if sev := rule.Severity(); int(sev) > result.MaxSeverity {
			result.MaxSeverity = int(sev)
		}
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
