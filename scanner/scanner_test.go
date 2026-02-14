package scanner

import (
	"context"
	"errors"
	"math/rand"
	"testing"
	"time"
)

func TestScanEndpointsAggregatesResults(t *testing.T) {
	probe := func(ctx context.Context, endpoint string, o Options) error {
		if endpoint == "ok:443" {
			return nil
		}
		if endpoint == "slow:443" {
			<-ctx.Done()
			return ctx.Err()
		}
		return errors.New("boom")
	}

	results := ScanEndpoints(
		[]string{"ok:443", "bad:443", "slow:443"},
		WithPerIPTimeout(20*time.Millisecond),
		WithProbe(probe),
	)

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	if !results[0].OK {
		t.Fatalf("expected first endpoint to be healthy")
	}
	if results[1].OK || results[1].Err == "" {
		t.Fatalf("expected second endpoint to fail with error")
	}
	if results[2].OK || results[2].Err == "" {
		t.Fatalf("expected third endpoint to fail with timeout")
	}
}

func TestPickRandomHealthy(t *testing.T) {
	results := []Result{
		{Endpoint: "a:443", OK: false},
		{Endpoint: "b:443", OK: true},
		{Endpoint: "c:443", OK: true},
	}

	picked, err := PickRandomHealthy(results, rand.New(rand.NewSource(1)))
	if err != nil {
		t.Fatalf("PickRandomHealthy() error = %v", err)
	}
	if picked != "c:443" {
		t.Fatalf("unexpected picked endpoint: %s", picked)
	}
}

func TestPickRandomHealthyNoCandidate(t *testing.T) {
	_, err := PickRandomHealthy([]Result{{Endpoint: "a", OK: false}}, nil)
	if err == nil {
		t.Fatalf("expected error when no healthy endpoints")
	}
}
