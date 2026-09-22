package middleware

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestRateLimiterAllowsUpToTheBudgetThenRefuses(t *testing.T) {
	l := NewRateLimiter(3)
	for i := 1; i <= 3; i++ {
		if !l.Allow("device") {
			t.Fatalf("request %d was refused inside the budget", i)
		}
	}
	if l.Allow("device") {
		t.Error("the fourth request was admitted past a budget of 3")
	}
}

func TestRateLimiterKeepsKeysIndependent(t *testing.T) {
	l := NewRateLimiter(1)
	if !l.Allow("first") || !l.Allow("second") {
		t.Error("two distinct keys shared one budget")
	}
	if l.Allow("first") {
		t.Error("a key's budget was not spent")
	}
}

func TestRateLimiterResetsWhenTheWindowRollsOver(t *testing.T) {
	l := NewRateLimiter(1)
	if !l.Allow("device") {
		t.Fatal("first request refused")
	}
	if l.Allow("device") {
		t.Fatal("budget of 1 admitted a second request")
	}
	// Age the bucket rather than sleeping a minute: the window is wall-clock, so
	// backdating start is exactly what the passage of time would do.
	l.mu.Lock()
	b := l.buckets["device"]
	b.start = b.start.Add(-2 * time.Minute)
	l.buckets["device"] = b
	l.mu.Unlock()

	if !l.Allow("device") {
		t.Error("the budget did not reset once the window rolled over")
	}
}

// TestRateLimiterDoesNotGrowWithoutBound is the reason this limiter was
// consolidated. The previous implementation swept only entries older than two
// minutes and only above 10k keys, so a flood of keys that were all fresh grew
// the map without limit — an unauthenticated caller could exhaust the heap of
// the process every enrollment protocol shares.
func TestRateLimiterDoesNotGrowWithoutBound(t *testing.T) {
	l := NewRateLimiter(60)
	for i := range 4 * maxRateBuckets {
		l.Allow(fmt.Sprintf("attacker-%d", i))
	}
	l.mu.Lock()
	size := len(l.buckets)
	l.mu.Unlock()
	if size > maxRateBuckets {
		t.Errorf("tracked %d keys, want at most %d", size, maxRateBuckets)
	}
}

// TestRateLimiterStillServesKnownKeysAtCapacity checks the denial at the cap is
// not indiscriminate: a caller already inside its window keeps its budget, so a
// flood of new keys degrades new callers rather than cutting off a fleet
// mid-enrollment.
func TestRateLimiterStillServesKnownKeysAtCapacity(t *testing.T) {
	l := NewRateLimiter(60)
	if !l.Allow("known device") {
		t.Fatal("first request refused")
	}
	for i := range 2 * maxRateBuckets {
		l.Allow(fmt.Sprintf("attacker-%d", i))
	}
	if !l.Allow("known device") {
		t.Error("a caller already inside its window was refused because the map was full")
	}
}

func TestRateLimiterIsSafeUnderConcurrentUse(t *testing.T) {
	l := NewRateLimiter(1000)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := range 200 {
				l.Allow(fmt.Sprintf("key-%d-%d", n, j%10))
			}
		}(i)
	}
	wg.Wait()
}
