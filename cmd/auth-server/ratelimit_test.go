package main

import (
	"testing"
	"time"

	"github.com/misaka-cpu/nft-auth-whitelist/internal/config"
)

func TestFailureLimiterDropsExpiredBuckets(t *testing.T) {
	f := newFailureLimiter(config.RateLimit{Enabled: true, MaxFailuresPerMinute: 10})
	now := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)

	for _, peer := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		if f.blocked(peer, now) {
			t.Fatalf("%s should not be blocked on first failure", peer)
		}
	}

	later := now.Add(time.Minute)
	if f.blocked("4.4.4.4", later) {
		t.Fatal("new peer should not be blocked")
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.buckets) != 1 {
		t.Fatalf("expired buckets were not cleaned up, got %d buckets", len(f.buckets))
	}
	if _, ok := f.buckets["4.4.4.4"]; !ok {
		t.Fatal("current peer bucket missing after cleanup")
	}
}
