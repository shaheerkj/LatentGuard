package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/shaheerkj/latentguard/proxy/internal/client"
	"github.com/shaheerkj/latentguard/proxy/internal/coraza"
	"github.com/shaheerkj/latentguard/proxy/internal/pipeline"
	"github.com/shaheerkj/latentguard/proxy/internal/storage"
	"github.com/shaheerkj/latentguard/proxy/internal/threatintel"
	"github.com/shaheerkj/latentguard/proxy/internal/tlsutil"
)

type config struct {
	listen        string
	tlsListen     string
	tlsCertFile   string
	tlsKeyFile    string
	upstreamURL   string
	mlURL         string
	mlTimeout     time.Duration
	mongoURI      string
	mongoDB       string
	rulesDir      string
	tiEnabled     bool
	tiURLs        []string
	tiRefresh     time.Duration
	tiTimeout     time.Duration
	tiDataPath    string
}

func loadConfig() config {
	timeoutMS, _ := strconv.Atoi(env("ML_TIMEOUT_MS", "250"))
	tiRefreshH, _ := strconv.Atoi(env("THREATINTEL_REFRESH_HOURS", "12"))
	tiTimeoutS, _ := strconv.Atoi(env("THREATINTEL_TIMEOUT_SEC", "15"))
	rulesDir := env("CORAZA_RULES_DIR", "./rules")
	// Default sources: Spamhaus DROP + EDROP (free, no API key, ~1.5k CIDRs).
	defaultURLs := "https://www.spamhaus.org/drop/drop.txt,https://www.spamhaus.org/drop/edrop.txt"
	return config{
		listen:      env("PROXY_LISTEN", ":8080"),
		tlsListen:   env("PROXY_TLS_LISTEN", ":8443"),
		tlsCertFile: env("PROXY_TLS_CERT", ""),
		tlsKeyFile:  env("PROXY_TLS_KEY", ""),
		upstreamURL: env("PROXY_UPSTREAM", "http://localhost:8081"),
		mlURL:       env("ML_URL", "http://localhost:8000"),
		mlTimeout:   time.Duration(timeoutMS) * time.Millisecond,
		mongoURI:    env("MONGO_URI", "mongodb://localhost:27017"),
		mongoDB:     env("MONGO_DB", "latentguard"),
		rulesDir:    rulesDir,
		tiEnabled:   envBool("THREATINTEL_ENABLED", true),
		tiURLs:      splitCSV(env("THREATINTEL_URL", defaultURLs)),
		tiRefresh:   time.Duration(tiRefreshH) * time.Hour,
		tiTimeout:   time.Duration(tiTimeoutS) * time.Second,
		// Coraza @ipMatchFromFile resolves paths relative to the rule file,
		// so the data file MUST sit next to 20-threat-intel.conf.
		tiDataPath: filepath.Join(rulesDir, "threatintel.data"),
	}
}

func envBool(key string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if v == "" {
		return def
	}
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	cfg := loadConfig()
	log.Printf("LatentGuard proxy starting; listen=%s upstream=%s ml=%s mongo=%s rules=%s",
		cfg.listen, cfg.upstreamURL, cfg.mlURL, cfg.mongoURI, cfg.rulesDir)

	upstream, err := url.Parse(cfg.upstreamURL)
	if err != nil {
		log.Fatalf("invalid PROXY_UPSTREAM %q: %v", cfg.upstreamURL, err)
	}

	// Make sure threatintel.data exists before Coraza parses the rule that
	// references it -- otherwise @ipMatchFromFile fails to load on a fresh
	// clone where the fetcher has never run.
	if err := threatintel.EnsurePlaceholder(cfg.tiDataPath); err != nil {
		log.Fatalf("threatintel placeholder: %v", err)
	}

	wafEngine, err := coraza.New(cfg.rulesDir)
	if err != nil {
		log.Fatalf("coraza init failed: %v", err)
	}

	tiManager := threatintel.NewManager(threatintel.Config{
		Enabled:    cfg.tiEnabled,
		URLs:       cfg.tiURLs,
		OutputPath: cfg.tiDataPath,
		Refresh:    cfg.tiRefresh,
		Timeout:    cfg.tiTimeout,
	}, wafEngine)

	bootCtx, bootCancel := context.WithTimeout(context.Background(), 10*time.Second)
	store, err := storage.Connect(bootCtx, cfg.mongoURI, cfg.mongoDB)
	bootCancel()
	if err != nil {
		log.Printf("WARN: mongo connect failed (%v); proxy will run without audit logging", err)
		store = nil
	}

	mlc := client.New(cfg.mlURL, cfg.mlTimeout)
	safe := &pipeline.SafeMode{}
	go pipeline.Heartbeat(mlc, safe, 5*time.Second)

	// Threat-intel: blocking boot fetch (fail-soft), then ticker. Runs in its
	// own context so a graceful shutdown stops the goroutine cleanly.
	tiCtx, tiCancel := context.WithCancel(context.Background())
	defer tiCancel()
	tiManager.Start(tiCtx)

	reverse := httputil.NewSingleHostReverseProxy(upstream)
	reverse.Director = func(r *http.Request) {
		r.URL.Scheme = upstream.Scheme
		r.URL.Host = upstream.Host
		r.Host = upstream.Host
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/__healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/__safe-mode", func(w http.ResponseWriter, _ *http.Request) {
		if safe.Get() {
			_, _ = w.Write([]byte(`{"safe_mode":true}`))
		} else {
			_, _ = w.Write([]byte(`{"safe_mode":false}`))
		}
	})
	mux.HandleFunc("/__threatintel", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tiManager.Status())
	})
	mux.Handle("/", pipeline.Handler(wafEngine, mlc, store, safe, reverse))

	server := &http.Server{
		Addr:              cfg.listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// HTTPS listener (Module 1 / FE-2: TLS termination at the proxy edge so we
	// can inspect plaintext before forwarding upstream). Runs in parallel with
	// the HTTP listener — same handler, same Coraza/ML/audit pipeline.
	cert, certSource, err := tlsutil.Load(cfg.tlsCertFile, cfg.tlsKeyFile)
	if err != nil {
		log.Fatalf("tls cert: %v", err)
	}
	tlsServer := &http.Server{
		Addr:              cfg.tlsListen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("listening on %s (HTTP)", cfg.listen)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	}()

	go func() {
		log.Printf("listening on %s (HTTPS, cert=%s)", cfg.tlsListen, certSource)
		if err := tlsServer.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("tls server error: %v", err)
		}
	}()

	<-stop
	log.Println("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
	_ = tlsServer.Shutdown(ctx)
	if store != nil {
		_ = store.Close(ctx)
	}
}
