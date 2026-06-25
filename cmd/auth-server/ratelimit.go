package main

import (
	"sync"
	"time"

	"github.com/misaka-cpu/nft-auth-whitelist/internal/config"
)

// failureLimiter throttles repeated failed Basic Auth attempts per peer using a
// simple fixed one-minute window counter. It is intentionally lightweight and
// in-memory only.
type failureLimiter struct {
	enabled bool
	max     int
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	windowStart time.Time
	count       int
}

func newFailureLimiter(rl config.RateLimit) *failureLimiter {
	return &failureLimiter{
		enabled: rl.Enabled,
		max:     rl.MaxFailuresPerMinute,
		buckets: make(map[string]*bucket),
	}
}

// blocked records a failure for peer and reports whether the peer has now
// exceeded the per-minute failure budget.
func (f *failureLimiter) blocked(peer string, now time.Time) bool {
	if !f.enabled || f.max <= 0 {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	f.cleanupExpiredLocked(now)

	b := f.buckets[peer]
	if b == nil || now.Sub(b.windowStart) >= time.Minute {
		b = &bucket{windowStart: now, count: 0}
		f.buckets[peer] = b
	}
	b.count++
	return b.count > f.max
}

func (f *failureLimiter) cleanupExpiredLocked(now time.Time) {
	for peer, b := range f.buckets {
		if now.Sub(b.windowStart) >= time.Minute {
			delete(f.buckets, peer)
		}
	}
}
