// Package storage implements the proxy's slice of SRS Module M7: append-only
// audit storage of every intercepted request and the decision rendered.
package storage

import (
	"context"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// AuditRecord is the shape written into the `requests` collection.
type AuditRecord struct {
	RequestID      string                 `bson:"request_id"`
	Timestamp      time.Time              `bson:"timestamp"`
	SourceIP       string                 `bson:"source_ip"`
	Method         string                 `bson:"method"`
	Path           string                 `bson:"path"`
	CanonicalPath  string                 `bson:"canonical_path"`
	CanonicalQuery string                 `bson:"canonical_query"`
	CanonicalBody  string                 `bson:"canonical_body"`
	Headers        map[string]string      `bson:"headers"`
	Features       map[string]interface{} `bson:"features"`
	RuleAction     string                 `bson:"rule_action"`
	RuleHits       []int                  `bson:"rule_hits"`
	MLAction       string                 `bson:"ml_action"`
	MLScore        float64                `bson:"ml_score"`
	MLAnomalyScore float64                `bson:"ml_anomaly_score"`
	MLOutlierScore float64                `bson:"ml_outlier_score"`
	RuleScore      float64                `bson:"rule_score"`
	FinalAction    string                 `bson:"final_action"`
	FallbackUsed   bool                   `bson:"fallback_used"`
	Reasons        []string               `bson:"reasons"`
	LatencyMS      int64                  `bson:"latency_ms"`
}

// Store wraps the Mongo client and the audit collection.
type Store struct {
	client   *mongo.Client
	requests *mongo.Collection
}

// Connect dials Mongo, ensures indexes, and returns a ready Store.
func Connect(ctx context.Context, uri, dbName string) (*Store, error) {
	cli, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return nil, err
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := cli.Ping(pingCtx, nil); err != nil {
		return nil, err
	}

	col := cli.Database(dbName).Collection("requests")
	if err := ensureIndexes(ctx, col); err != nil {
		return nil, err
	}
	return &Store{client: cli, requests: col}, nil
}

func ensureIndexes(ctx context.Context, col *mongo.Collection) error {
	models := []mongo.IndexModel{
		{Keys: bson.D{{Key: "timestamp", Value: -1}}},
		{Keys: bson.D{{Key: "request_id", Value: 1}}, Options: options.Index().SetUnique(true)},
		{Keys: bson.D{{Key: "final_action", Value: 1}, {Key: "timestamp", Value: -1}}},
		{Keys: bson.D{{Key: "source_ip", Value: 1}, {Key: "timestamp", Value: -1}}},
	}
	_, err := col.Indexes().CreateMany(ctx, models)
	return err
}

// Append writes a single audit record. Errors are logged but never block the
// request hot path — losing a log line is preferable to dropping a request.
func (s *Store) Append(ctx context.Context, rec AuditRecord) {
	if s == nil || s.requests == nil {
		return
	}
	insertCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if _, err := s.requests.InsertOne(insertCtx, rec); err != nil {
		log.Printf("storage: append failed: %v", err)
	}
}

// Close shuts the underlying Mongo client.
func (s *Store) Close(ctx context.Context) error {
	if s == nil || s.client == nil {
		return nil
	}
	return s.client.Disconnect(ctx)
}
