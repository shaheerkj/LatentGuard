package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/shaheerkj/latentguard/proxy/internal/client"
	"github.com/shaheerkj/latentguard/proxy/internal/coraza"
	"github.com/shaheerkj/latentguard/proxy/internal/pipeline"
	"github.com/shaheerkj/latentguard/proxy/internal/storage"
)

type config struct {
	listen      string
	upstreamURL string
	mlURL       string
	mlTimeout   time.Duration
	mongoURI    string
	mongoDB     string
	rulesDir    string
}

func loadConfig() config {
	timeoutMS, _ := strconv.Atoi(env("ML_TIMEOUT_MS", "250"))
	return config{
		listen:      env("PROXY_LISTEN", ":8080"),
		upstreamURL: env("PROXY_UPSTREAM", "http://localhost:8081"),
		mlURL:       env("ML_URL", "http://localhost:8000"),
		mlTimeout:   time.Duration(timeoutMS) * time.Millisecond,
		mongoURI:    env("MONGO_URI", "mongodb://localhost:27017"),
		mongoDB:     env("MONGO_DB", "latentguard"),
		rulesDir:    env("CORAZA_RULES_DIR", "./rules"),
	}
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

	wafEngine, err := coraza.New(cfg.rulesDir)
	if err != nil {
		log.Fatalf("coraza init failed: %v", err)
	}

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
	mux.Handle("/", pipeline.Handler(wafEngine, mlc, store, safe, reverse))

	server := &http.Server{
		Addr:              cfg.listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("listening on %s", cfg.listen)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-stop
	log.Println("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
	if store != nil {
		_ = store.Close(ctx)
	}
}
