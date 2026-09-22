package middleware

import (
	"sync"
	"time"
)

// maxRateBuckets caps how many keys the limiter will track at once.
//
// The sweep below reclaims windows that have rolled over, which handles honest
// traffic. It does not handle a flood of keys that are all fresh, so the cap is
// what stops the map from growing without bound. At the cap the limiter denies
// rather than admits: refusing under memory pressure costs some enrollments,
// while admitting would let one caller exhaust the process every protocol in
// this service shares.
//
// That denial is only reachable when a caller can mint distinct keys faster than
// they expire, which is why ClientIP ignores forwarded headers from peers that
// are not configured proxies — without that, the key is attacker-chosen and this
// cap is the only thing between a flood and the heap.
const maxRateBuckets = 50000

// sweepInterval bounds how often a full walk of the bucket map may run.
const sweepInterval = 10 * time.Second

type rateBucket struct {
	start time.Time
	count int
}

// RateLimiter is a fixed-window per-key counter, shared by the SCEP, ACME and
// EST endpoints. They hold separate instances rather than one shared budget:
// their traffic shapes differ by orders of magnitude — EST sees one or two
// requests per device per year where ACME polls many times per enrollment — and
// one protocol's burst must not spend another's allowance.
//
// It is per-process, which makes it a courtesy under a load balancer rather than
// a control. The controls that matter are the credential, the nonce, the
// signature and transaction state, all of which live in the database. The one
// place it carries real weight is EST, where it bounds how often an
// unauthenticated caller can make the server compute argon2id.
type RateLimiter struct {
	mu        sync.Mutex
	limit     int
	buckets   map[string]rateBucket
	lastSweep time.Time
}

// NewRateLimiter returns a limiter admitting limit requests per key per minute.
func NewRateLimiter(limit int) *RateLimiter {
	return &RateLimiter{limit: limit, buckets: map[string]rateBucket{}}
}

// Allow records one request against key and reports whether it is within budget.
func (l *RateLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	if len(l.buckets) >= maxRateBuckets {
		// Sweeping walks the whole map, so it is throttled. Doing it on every
		// call at capacity would make each request O(len(buckets)) during exactly
		// the flood this cap exists to survive — turning a memory problem into a
		// worse CPU one. Windows are a minute wide, so nothing is retained
		// meaningfully longer by waiting between sweeps.
		if now.Sub(l.lastSweep) >= sweepInterval {
			l.lastSweep = now
			for k, candidate := range l.buckets {
				// A rolled-over window would be reset on its next use anyway, so
				// dropping it loses nothing.
				if now.Sub(candidate.start) >= time.Minute {
					delete(l.buckets, k)
				}
			}
		}
		// Still full: every tracked key is inside its current window, so this is
		// a flood rather than a backlog. Deny new keys without inserting, or the
		// map grows past the cap. Keys already tracked keep their budget, so a
		// flood degrades new callers rather than cutting off a fleet mid-renewal.
		if _, tracked := l.buckets[key]; !tracked && len(l.buckets) >= maxRateBuckets {
			return false
		}
	}

	b := l.buckets[key]
	if now.Sub(b.start) >= time.Minute {
		b = rateBucket{start: now}
	}
	b.count++
	l.buckets[key] = b
	return b.count <= l.limit
}
