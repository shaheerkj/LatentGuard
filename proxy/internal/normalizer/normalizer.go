// Package normalizer implements SRS Module M2: request canonicalization and
// feature extraction. The output Normalized struct is the contract that the
// ML scoring service consumes via /score.
package normalizer

import (
	"math"
	"net/http"
	"net/url"
	"strings"
	"unicode"
)

// Features matches the NormalizedFeatures schema in ml/app/schemas.py.
type Features struct {
	Length         int     `json:"length"`
	Entropy        float64 `json:"entropy"`
	TokenCount     int     `json:"token_count"`
	SpecialRatio   float64 `json:"special_ratio"`
	DigitRatio     float64 `json:"digit_ratio"`
	UppercaseRatio float64 `json:"uppercase_ratio"`
	MethodIsPost   bool    `json:"method_is_post"`
}

// Normalized is the canonicalized view of an HTTP request used for scoring,
// rule matching, and audit storage.
type Normalized struct {
	Method         string   `json:"method"`
	Path           string   `json:"path"`
	CanonicalPath  string   `json:"canonical_path"`
	CanonicalQuery string   `json:"canonical_query"`
	CanonicalBody  string   `json:"canonical_body"`
	Features       Features `json:"features"`
}

// Normalize builds a Normalized from an http.Request plus a pre-buffered body
// (the proxy reads the body once and reuses it for both Coraza and the ML
// service, so passing it explicitly keeps responsibilities clean).
func Normalize(r *http.Request, body []byte) Normalized {
	canonicalPath := canonicalizePath(r.URL.Path)
	canonicalQuery := canonicalizeQuery(r.URL.Query())
	canonicalBody := strings.ToLower(strings.TrimSpace(string(body)))

	combined := canonicalPath + " " + canonicalQuery + " " + canonicalBody

	return Normalized{
		Method:         r.Method,
		Path:           r.URL.Path,
		CanonicalPath:  canonicalPath,
		CanonicalQuery: canonicalQuery,
		CanonicalBody:  canonicalBody,
		Features:       extractFeatures(combined, r.Method),
	}
}

func canonicalizePath(p string) string {
	if p == "" {
		return "/"
	}
	lower := strings.ToLower(p)
	// Collapse repeated slashes — a common evasion trick.
	for strings.Contains(lower, "//") {
		lower = strings.ReplaceAll(lower, "//", "/")
	}
	return lower
}

func canonicalizeQuery(values url.Values) string {
	if len(values) == 0 {
		return ""
	}
	// Lowercase keys but keep the original values associated with them.
	lowered := make(map[string][]string, len(values))
	keys := make([]string, 0, len(values))
	for k, vs := range values {
		lk := strings.ToLower(k)
		if _, ok := lowered[lk]; !ok {
			keys = append(keys, lk)
		}
		lowered[lk] = append(lowered[lk], vs...)
	}
	sortStrings(keys)

	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(strings.ToLower(strings.Join(lowered[k], ",")))
	}
	return b.String()
}

func sortStrings(xs []string) {
	// Inline insertion sort — small n, avoids importing "sort" for one call.
	for i := 1; i < len(xs); i++ {
		for j := i; j > 0 && xs[j-1] > xs[j]; j-- {
			xs[j-1], xs[j] = xs[j], xs[j-1]
		}
	}
}

func extractFeatures(text string, method string) Features {
	length := len(text)
	if length == 0 {
		return Features{MethodIsPost: strings.EqualFold(method, http.MethodPost)}
	}

	var digits, uppers, specials int
	freq := make(map[rune]int, 64)
	tokenCount := 0
	inToken := false

	for _, r := range text {
		freq[r]++
		switch {
		case unicode.IsDigit(r):
			digits++
		case unicode.IsUpper(r):
			uppers++
		case !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.IsSpace(r):
			specials++
		}
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			if !inToken {
				tokenCount++
				inToken = true
			}
		} else {
			inToken = false
		}
	}

	return Features{
		Length:         length,
		Entropy:        shannonEntropy(freq, length),
		TokenCount:     tokenCount,
		SpecialRatio:   ratio(specials, length),
		DigitRatio:     ratio(digits, length),
		UppercaseRatio: ratio(uppers, length),
		MethodIsPost:   strings.EqualFold(method, http.MethodPost),
	}
}

func shannonEntropy(freq map[rune]int, total int) float64 {
	if total <= 0 {
		return 0
	}
	var h float64
	n := float64(total)
	for _, c := range freq {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	// Round to 4 decimals to match the Python normalizer convention.
	return math.Round(h*10000) / 10000
}

func ratio(part, total int) float64 {
	if total <= 0 {
		return 0
	}
	return math.Round((float64(part)/float64(total))*10000) / 10000
}
