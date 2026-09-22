// Package worker drives the background sweeps that outlive a request.
//
// It exists because all four of them — CRL renewal, expiry alerts, ACME order
// expiry, Intune revocation sync — had written the same loop, and every copy was
// missing the same thing: middleware.Recover wraps the HTTP handler chain and
// nothing else, so a nil dereference in a CRL publication or a malformed Intune
// response took down the whole process. A goroutine that panics is not recovered
// by anything above it.
package worker

import (
	"context"
	"log"
	"runtime/debug"
	"time"
)

// Run calls once immediately and then on every tick until ctx is cancelled.
//
// Immediately rather than after the first interval: a deploy restarts the
// process, and a sweep that waited an hour to start would leave anything that
// fell due during the restart unattended for that hour.
//
// Cancellation is checked before the tick so a SIGTERM stops the loop between
// units of work rather than in the middle of one. Each sweep holds a database
// transaction, so being interrupted partway is what leaves a connection for
// Postgres to time out.
func Run(ctx context.Context, name string, interval time.Duration, once func(context.Context) error) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		runOnce(ctx, name, once)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// runOnce is a separate function because a deferred recover only fires when the
// function holding it returns — a recover inside Run's loop body would still let
// the panic escape the loop, which is the whole failure this guards against. One
// panic costs one tick.
func runOnce(ctx context.Context, name string, once func(context.Context) error) {
	defer func() {
		if v := recover(); v != nil {
			// The stack is logged because there is nothing else to look at: these
			// run unattended, and a panic here produces no request, no status code
			// and no user to report it.
			log.Printf("%s panicked, continuing at the next interval: %v\n%s", name, v, debug.Stack())
		}
	}()
	// ctx.Err() suppresses the error a cancelled sweep reports on the way out.
	// Shutdown is not a failure, and logging it as one trains people to ignore
	// the line that matters.
	if err := once(ctx); err != nil && ctx.Err() == nil {
		log.Printf("%s failed: %v", name, err)
	}
}
