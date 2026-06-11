package api

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

type fakeResolver struct {
	mu      sync.Mutex
	calls   int
	results map[string]net.IP
	errs    map[string]error
	delay   time.Duration
}

func newFakeResolver() *fakeResolver {
	return &fakeResolver{
		results: make(map[string]net.IP),
		errs:    make(map[string]error),
	}
}

func (f *fakeResolver) addResult(name string, ip net.IP) {
	f.results[name] = ip
}

func (f *fakeResolver) addError(name string, err error) {
	f.errs[name] = err
}

func (f *fakeResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return ctx, nil, ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if err, ok := f.errs[name]; ok {
		return ctx, nil, err
	}
	if ip, ok := f.results[name]; ok {
		return ctx, ip, nil
	}
	return ctx, nil, errors.New("not found")
}

func TestCachingResolver_Hit(t *testing.T) {
	inner := newFakeResolver()
	inner.addResult("example.com", net.ParseIP("1.2.3.4"))

	r := NewCachingResolver(inner, time.Minute, time.Second, 10)

	ctx := context.Background()
	_, ip1, err := r.Resolve(ctx, "example.com")
	if err != nil {
		t.Fatalf("first resolve failed: %v", err)
	}
	if !ip1.Equal(net.ParseIP("1.2.3.4")) {
		t.Fatalf("unexpected ip: %v", ip1)
	}

	_, ip2, err := r.Resolve(ctx, "example.com")
	if err != nil {
		t.Fatalf("second resolve failed: %v", err)
	}
	if !ip2.Equal(net.ParseIP("1.2.3.4")) {
		t.Fatalf("unexpected ip on second resolve: %v", ip2)
	}

	if inner.calls != 1 {
		t.Fatalf("expected 1 upstream call, got %d", inner.calls)
	}
}

func TestCachingResolver_Singleflight(t *testing.T) {
	inner := newFakeResolver()
	inner.delay = 50 * time.Millisecond
	inner.addResult("example.com", net.ParseIP("1.2.3.4"))

	r := NewCachingResolver(inner, time.Minute, time.Second, 10)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _ = r.Resolve(context.Background(), "example.com")
		}()
	}
	wg.Wait()

	if inner.calls != 1 {
		t.Fatalf("expected 1 upstream call with singleflight, got %d", inner.calls)
	}
}

func TestCachingResolver_NegativeCache(t *testing.T) {
	inner := newFakeResolver()
	inner.addError("bad.example", errors.New("dns error"))

	r := NewCachingResolver(inner, time.Minute, 200*time.Millisecond, 10)
	ctx := context.Background()

	_, _, err1 := r.Resolve(ctx, "bad.example")
	if err1 == nil {
		t.Fatal("expected error on first resolve")
	}

	_, _, err2 := r.Resolve(ctx, "bad.example")
	if err2 == nil {
		t.Fatal("expected error on second resolve")
	}

	if inner.calls != 1 {
		t.Fatalf("expected 1 upstream call due to negative cache, got %d", inner.calls)
	}

	// Wait for negative TTL to expire.
	time.Sleep(300 * time.Millisecond)
	_, _, _ = r.Resolve(ctx, "bad.example")
	if inner.calls != 2 {
		t.Fatalf("expected 2 upstream calls after negative TTL expiry, got %d", inner.calls)
	}
}

func TestCachingResolver_Eviction(t *testing.T) {
	inner := newFakeResolver()
	inner.addResult("a.com", net.ParseIP("1.1.1.1"))
	inner.addResult("b.com", net.ParseIP("2.2.2.2"))
	inner.addResult("c.com", net.ParseIP("3.3.3.3"))

	r := NewCachingResolver(inner, time.Minute, time.Second, 2)
	ctx := context.Background()

	// Fill cache to capacity.
	_, _, _ = r.Resolve(ctx, "a.com")
	_, _, _ = r.Resolve(ctx, "b.com")

	if len(r.cache) != 2 {
		t.Fatalf("expected cache size 2, got %d", len(r.cache))
	}

	// Trigger eviction by adding a third entry.
	_, _, _ = r.Resolve(ctx, "c.com")

	if len(r.cache) > 2 {
		t.Fatalf("expected cache size <= 2 after eviction, got %d", len(r.cache))
	}

	// The oldest entry may have been evicted; querying it should hit upstream again.
	callsBefore := inner.calls
	_, _, _ = r.Resolve(ctx, "a.com")
	if inner.calls == callsBefore {
		t.Fatal("expected upstream call after eviction")
	}
}

func TestTunnelDNSResolver_Race(t *testing.T) {
	// This test verifies that TunnelDNSResolver compiles and its Resolve
	// signature is correct. Full integration test requires a real netstack.Net.
	_ = TunnelDNSResolver{}
}

func TestLocalDNSResolver_BackwardCompatibility(t *testing.T) {
	// Verify that NewCachingDNSResolver still returns a usable resolver.
	// We can't do real DNS queries in unit tests, so just verify the type.
	r := NewCachingDNSResolver("8.8.8.8:53", time.Second)
	if r == nil {
		t.Fatal("expected non-nil resolver")
	}
}

func TestCachingResolver_ClearCache(t *testing.T) {
	inner := newFakeResolver()
	inner.addResult("example.com", net.ParseIP("1.2.3.4"))

	r := NewCachingResolver(inner, time.Minute, time.Second, 10)
	ctx := context.Background()

	_, _, _ = r.Resolve(ctx, "example.com")
	if len(r.cache) != 1 {
		t.Fatalf("expected cache size 1, got %d", len(r.cache))
	}

	r.ClearCache()
	if len(r.cache) != 0 {
		t.Fatalf("expected cache size 0 after clear, got %d", len(r.cache))
	}
}

func TestCachingResolver_TTLExpiration(t *testing.T) {
	inner := newFakeResolver()
	inner.addResult("example.com", net.ParseIP("1.2.3.4"))

	r := NewCachingResolver(inner, 100*time.Millisecond, time.Second, 10)
	ctx := context.Background()

	_, _, _ = r.Resolve(ctx, "example.com")
	if inner.calls != 1 {
		t.Fatalf("expected 1 call, got %d", inner.calls)
	}

	time.Sleep(150 * time.Millisecond)
	_, _, _ = r.Resolve(ctx, "example.com")
	if inner.calls != 2 {
		t.Fatalf("expected 2 calls after TTL expiry, got %d", inner.calls)
	}
}

func TestCachingResolver_ConcurrentMixedQueries(t *testing.T) {
	inner := newFakeResolver()
	inner.delay = 50 * time.Millisecond
	inner.addResult("a.com", net.ParseIP("1.1.1.1"))
	inner.addResult("b.com", net.ParseIP("2.2.2.2"))

	r := NewCachingResolver(inner, time.Minute, time.Second, 10)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _, _ = r.Resolve(context.Background(), "a.com")
		}()
		go func() {
			defer wg.Done()
			_, _, _ = r.Resolve(context.Background(), "b.com")
		}()
	}
	wg.Wait()

	// Should be exactly 2 upstream calls (one per unique name).
	if inner.calls != 2 {
		t.Fatalf("expected 2 upstream calls, got %d", inner.calls)
	}
}
