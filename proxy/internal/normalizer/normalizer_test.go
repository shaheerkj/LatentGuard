package normalizer

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNormalize_BasicGET(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/Login?User=Bob&Pass=secret", nil)
	n := Normalize(r, nil)

	if n.CanonicalPath != "/login" {
		t.Errorf("path: got %q want /login", n.CanonicalPath)
	}
	if n.CanonicalQuery != "pass=secret&user=bob" {
		t.Errorf("query: got %q want pass=secret&user=bob", n.CanonicalQuery)
	}
	if n.Features.MethodIsPost {
		t.Errorf("MethodIsPost should be false for GET")
	}
	if n.Features.TokenCount == 0 {
		t.Errorf("expected non-zero token count")
	}
	if n.Features.Entropy == 0 {
		t.Errorf("expected non-zero entropy")
	}
}

func TestNormalize_PostWithBody(t *testing.T) {
	body := strings.NewReader("comment=<script>alert(1)</script>")
	r := httptest.NewRequest(http.MethodPost, "/Comments//submit", body)
	n := Normalize(r, []byte("comment=<script>alert(1)</script>"))

	if n.CanonicalPath != "/comments/submit" {
		t.Errorf("path collapse failed: %q", n.CanonicalPath)
	}
	if !n.Features.MethodIsPost {
		t.Errorf("MethodIsPost should be true for POST")
	}
	if n.Features.SpecialRatio == 0 {
		t.Errorf("expected special ratio > 0 for XSS-ish body")
	}
}

func TestNormalize_EmptyRequest(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	n := Normalize(r, nil)
	if n.CanonicalPath != "/" {
		t.Errorf("expected /, got %q", n.CanonicalPath)
	}
	if n.CanonicalQuery != "" {
		t.Errorf("expected empty query, got %q", n.CanonicalQuery)
	}
}

// Parity with ml/app/features.py _ngram_stats. Each row is a literal
// produced by the Python reference implementation (round to 4 places).
// If either implementation drifts, this test starts failing -- the
// scaler/AE then sees train/serve skew and silently mis-scores.
func TestNgramStatsParity(t *testing.T) {
	cases := []struct {
		text          string
		n             int
		wantH         float64
		wantUniqRatio float64
	}{
		{"abcabc", 3, 1.5, 0.75},
		{"abcabc", 4, 1.585, 1.0},
		{"hello world", 3, 3.1699, 1.0},
		{"aaa", 3, 0.0, 1.0},
		{"xx", 3, 0.0, 0.0},
	}
	for _, c := range cases {
		gotH, gotU := ngramStats(c.text, c.n)
		if gotH != c.wantH || gotU != c.wantUniqRatio {
			t.Errorf("ngramStats(%q, %d) = (%v, %v), want (%v, %v)",
				c.text, c.n, gotH, gotU, c.wantH, c.wantUniqRatio)
		}
	}
}
