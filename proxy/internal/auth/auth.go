// Package auth verifies the HS256 JWTs issued by the ML service's
// /api/auth/login endpoint. The same JWT_SECRET env var is shared between
// ML (FastAPI) and proxy (Go) so any token the dashboard holds is accepted
// by either side.
//
// Why on the proxy at all: the operator endpoints under /__* (threatintel
// status, safe-mode flag) leak operational state. They're called from the
// dashboard only, never the protected app traffic. Gating them behind the
// same JWT keeps the admin panel coherent -- "every request to the admin
// panel is auth-checked, no matter the path".
//
// /__healthz is deliberately UN-gated so docker compose healthchecks (and
// any future external probes) still work. It only returns "ok" -- no
// secrets leak through.
package auth

import (
	"errors"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// Verifier holds the shared secret. Build one at boot via NewVerifier(),
// then reuse for the process lifetime.
type Verifier struct {
	secret []byte
}

// NewVerifier reads JWT_SECRET from env. Empty secret is a hard error --
// unlike the ML side we never fall back to an ephemeral random secret
// here, because the proxy can't reach the ML side to coordinate one and
// the dashboard's token wouldn't verify either way.
//
// If JWT_SECRET is empty the verifier still constructs but every Verify
// call returns ErrNoSecret; the middleware will 503 instead of 401 so
// operators can tell "auth misconfigured" from "auth rejected".
func NewVerifier() *Verifier {
	s := strings.TrimSpace(os.Getenv("JWT_SECRET"))
	if s == "" {
		log.Println("WARN: JWT_SECRET is empty; proxy operator endpoints will return 503 until set")
	}
	return &Verifier{secret: []byte(s)}
}

var (
	ErrNoSecret    = errors.New("jwt secret not configured")
	ErrNoToken     = errors.New("missing bearer token")
	ErrBadToken    = errors.New("invalid token")
	ErrExpired     = errors.New("token expired")
	ErrWrongIssuer = errors.New("wrong issuer")
)

const expectedIssuer = "latentguard"

// Verify checks the standard "Authorization: Bearer ..." header against the
// shared secret. Returns the decoded claims on success.
func (v *Verifier) Verify(r *http.Request) (jwt.MapClaims, error) {
	if len(v.secret) == 0 {
		return nil, ErrNoSecret
	}
	h := r.Header.Get("Authorization")
	if h == "" {
		return nil, ErrNoToken
	}
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return nil, ErrNoToken
	}
	tok, err := jwt.Parse(parts[1], func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrBadToken
		}
		return v.secret, nil
	}, jwt.WithIssuer(expectedIssuer), jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpired
		}
		if errors.Is(err, jwt.ErrTokenInvalidIssuer) {
			return nil, ErrWrongIssuer
		}
		return nil, ErrBadToken
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok || !tok.Valid {
		return nil, ErrBadToken
	}
	return claims, nil
}

// Middleware wraps an http.Handler, requiring a valid JWT on every request.
// On failure writes a JSON error and the appropriate status code. On
// success calls the inner handler.
func (v *Verifier) Middleware(inner http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Let CORS preflights through; the browser won't carry credentials
		// on OPTIONS by default and the dashboard relies on the OPTIONS
		// succeeding to learn the allowed headers.
		if r.Method == http.MethodOptions {
			inner.ServeHTTP(w, r)
			return
		}
		_, err := v.Verify(r)
		if err == nil {
			inner.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("WWW-Authenticate", `Bearer realm="latentguard"`)
		switch {
		case errors.Is(err, ErrNoSecret):
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"auth misconfigured: JWT_SECRET unset"}`))
		case errors.Is(err, ErrExpired):
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"token expired"}`))
		default:
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
		}
	})
}
