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
// MUST stay in lock-step with ml/app/features.py: add fields here AND
// there in the same commit, or the autoencoder will see train/serve
// skew. Field order is preserved across the JSON boundary because the
// ML service builds its feature vector by name, not by position.
type Features struct {
	Length         int     `json:"length"`
	Entropy        float64 `json:"entropy"`
	TokenCount     int     `json:"token_count"`
	SpecialRatio   float64 `json:"special_ratio"`
	DigitRatio     float64 `json:"digit_ratio"`
	UppercaseRatio float64 `json:"uppercase_ratio"`
	MethodIsPost   bool    `json:"method_is_post"`
	// Character n-gram summary stats. See features.py for the rationale;
	// short version: entropy + unique-ratio over 3- and 4-grams pick up
	// short adversarial motifs the per-character ratios miss.
	Ngram3Entropy      float64 `json:"ngram3_entropy"`
	Ngram3UniqueRatio  float64 `json:"ngram3_unique_ratio"`
	Ngram4Entropy      float64 `json:"ngram4_entropy"`
	Ngram4UniqueRatio  float64 `json:"ngram4_unique_ratio"`
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

	ng3H, ng3Uniq := ngramStats(text, 3)
	ng4H, ng4Uniq := ngramStats(text, 4)
	return Features{
		Length:            length,
		Entropy:           shannonEntropy(freq, length),
		TokenCount:        tokenCount,
		SpecialRatio:      ratio(specials, length),
		DigitRatio:        ratio(digits, length),
		UppercaseRatio:    ratio(uppers, length),
		MethodIsPost:      strings.EqualFold(method, http.MethodPost),
		Ngram3Entropy:     ng3H,
		Ngram3UniqueRatio: ng3Uniq,
		Ngram4Entropy:     ng4H,
		Ngram4UniqueRatio: ng4Uniq,
	}
}

// ngramStats returns (entropy, unique_ratio) over the character n-gram
// distribution. Operates on bytes (not runes) so it matches the Python
// implementation -- features.py uses string slicing which is byte-based
// for ASCII payloads (the canonicalised text always is, since canonical
// path/query/body lowercase and strip but do not Unicode-normalise).
// Strings shorter than n collapse to (0, 0).
func ngramStats(text string, n int) (float64, float64) {
	if len(text) < n {
		return 0, 0
	}
	counts := make(map[string]int, len(text))
	total := 0
	for i := 0; i+n <= len(text); i++ {
		counts[text[i:i+n]]++
		total++
	}
	if total == 0 {
		return 0, 0
	}
	var h float64
	inv := 1.0 / float64(total)
	for _, c := range counts {
		p := float64(c) * inv
		h -= p * math.Log2(p)
	}
	h = math.Round(h*10000) / 10000
	uniq := math.Round((float64(len(counts))/float64(total))*10000) / 10000
	return h, uniq
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
