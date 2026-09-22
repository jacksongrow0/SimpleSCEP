package worker

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// TestRunSurvivesAPanic is the whole reason this package exists. Before it, a
// panic in any sweep terminated the process: the goroutine was launched from
// main with no recover above it, and middleware.Recover only wraps HTTP
// handlers. The test asserts the loop keeps ticking, not merely that the panic
// is swallowed — a recover that stopped the loop would trade a crash for a sweep
// that silently never runs again.
func TestRunSurvivesAPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var calls atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		Run(ctx, "test sweep", time.Millisecond, func(context.Context) error {
			if calls.Add(1) >= 3 {
				cancel()
				return nil
			}
			panic("boom")
		})
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
	if got := calls.Load(); got < 3 {
		t.Errorf("sweep ran %d times, want at least 3: the loop stopped at the first panic", got)
	}
}

// TestRunCallsOnceBeforeTheFirstTick pins the restart behaviour. The interval
// here is longer than the test would ever wait, so the only way this passes is
// if the first call happens immediately.
func TestRunCallsOnceBeforeTheFirstTick(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ran := make(chan struct{})
	go Run(ctx, "test sweep", time.Hour, func(context.Context) error {
		close(ran)
		cancel()
		return nil
	})

	select {
	case <-ran:
	case <-time.After(5 * time.Second):
		t.Fatal("Run waited for the first tick instead of sweeping at start")
	}
}

// TestRunStopsOnCancellation covers the shutdown path: main waits on these with
// a WaitGroup, so a loop that ignored cancellation would hang the deploy until
// the orchestrator killed the process.
func TestRunStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		Run(ctx, "test sweep", time.Hour, func(context.Context) error { return errors.New("ignored") })
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return for an already-cancelled context")
	}
}
