package pipeline

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/shaheerkj/latentguard/proxy/internal/client"
	"github.com/shaheerkj/latentguard/proxy/internal/coraza"
)

// rulesDir locates the proxy/rules directory relative to this test file.
func rulesDir(t *testing.T) string {
	t.Helper()
	_, here, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(here), "..", "..", "rules")
}

// upstreamServer returns 200 with a marker body — lets tests assert the
// request actually reached the protected app.
func upstreamServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream-ok:" + r.URL.Path))
	}))
}

// mlServer returns a stub /score (always allow) and /healthz.
func mlServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/score", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"action":         "allow",
			"score":          0.0,
			"anomaly_score":  0.0,
			"outlier_score":  0.0,
			"rule_score":     0.0,
			"reasons":        []string{"stub allow"},
			"fallback_used":  false,
		})
	})
	return httptest.NewServer(mux)
}

func newPipeline(t *testing.T, mlURL string) (http.Handler, *SafeMode) {
	t.Helper()
	waf, err := coraza.New(rulesDir(t))
	if err != nil {
		t.Fatalf("coraza init: %v", err)
	}
	mlc := client.New(mlURL, 500*time.Millisecond)
	safe := &SafeMode{}
	upstream := upstreamServer(t)
	t.Cleanup(upstream.Close)
	return Handler(waf, mlc, nil /* nil store ok */, safe, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Forward to the test upstream.
		req, _ := http.NewRequest(r.Method, upstream.URL+r.URL.RequestURI(), r.Body)
		req.Header = r.Header
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})), safe
}

func TestPipeline_BenignAllowed(t *testing.T) {
	ml := mlServer(t)
	defer ml.Close()
	h, _ := newPipeline(t, ml.URL)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/products?id=42", nil)
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "upstream-ok") {
		t.Errorf("upstream not reached: %q", rec.Body.String())
	}
	if rec.Header().Get("X-LatentGuard-Request-ID") == "" {
		t.Errorf("missing request ID header")
	}
}

func TestPipeline_SQLiBlockedByCoraza(t *testing.T) {
	ml := mlServer(t)
	defer ml.Close()
	h, _ := newPipeline(t, ml.URL)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/login?user=admin&pass=x'+OR+1=1--", nil)
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for SQLi, got %d body=%q", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "upstream-ok") {
		t.Errorf("upstream should not have been reached")
	}
}

func TestPipeline_MLDownTriggersSafeMode(t *testing.T) {
	// Point at a port no one is listening on.
	h, safe := newPipeline(t, "http://127.0.0.1:1") // port 1 is reserved/unused

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/products", nil)
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected benign request to succeed in safe mode, got %d", rec.Code)
	}
	if !safe.Get() {
		t.Errorf("safe mode should have been engaged after ML failure")
	}
}
