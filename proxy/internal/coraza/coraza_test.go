package coraza

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// rulesDir locates the ../../rules directory relative to this file. The tests
// load the same rule files the production proxy will load, so they exercise
// the baseline SecLang directly.
func rulesDir(t *testing.T) string {
	t.Helper()
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test file location")
	}
	return filepath.Join(filepath.Dir(here), "..", "..", "rules")
}

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := New(rulesDir(t))
	if err != nil {
		t.Fatalf("engine init: %v", err)
	}
	return e
}

func TestInspect_AllowsBenignTraffic(t *testing.T) {
	e := newTestEngine(t)
	r := httptest.NewRequest(http.MethodGet, "/products?id=42", nil)
	r.RemoteAddr = "1.2.3.4:5678"

	out := e.Inspect(r, nil)
	if out.Interruption != nil {
		t.Fatalf("benign request was blocked: %+v (matched=%v)", out.Interruption, out.MatchedRuleIDs)
	}
}

func TestInspect_BlocksSQLi(t *testing.T) {
	e := newTestEngine(t)
	r := httptest.NewRequest(http.MethodGet, "/search?q=1'+OR+1=1--", nil)
	r.RemoteAddr = "1.2.3.4:5678"

	out := e.Inspect(r, nil)
	if out.Interruption == nil {
		t.Fatalf("SQLi request not blocked; matched=%v", out.MatchedRuleIDs)
	}
	if !containsRule(out.MatchedRuleIDs, 1000001) {
		t.Errorf("expected baseline SQLi rule 1000001 to fire, got %v", out.MatchedRuleIDs)
	}
}

func TestInspect_BlocksXSS(t *testing.T) {
	e := newTestEngine(t)
	body := strings.NewReader("comment=<script>alert(1)</script>")
	r := httptest.NewRequest(http.MethodPost, "/comments", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "1.2.3.4:5678"

	out := e.Inspect(r, []byte("comment=<script>alert(1)</script>"))
	if out.Interruption == nil {
		t.Fatalf("XSS body not blocked; matched=%v", out.MatchedRuleIDs)
	}
}

func TestInspect_BlocksPathTraversal(t *testing.T) {
	e := newTestEngine(t)
	r := httptest.NewRequest(http.MethodGet, "/files?name=../../../etc/passwd", nil)
	r.RemoteAddr = "1.2.3.4:5678"

	out := e.Inspect(r, nil)
	if out.Interruption == nil {
		t.Fatalf("path traversal not blocked; matched=%v", out.MatchedRuleIDs)
	}
}

func containsRule(ids []int, target int) bool {
	for _, id := range ids {
		if id == target {
			return true
		}
	}
	return false
}
