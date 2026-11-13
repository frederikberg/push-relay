package main

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// idleLimiterTTL is how long a per-key limiter (one per ticket_id, one per source IP) is kept
// around with no traffic before it is swept. Generous relative to every bucket's own window
// (at most a day) so a legitimate caller's burst allowance survives a quiet spell, while a
// one-off caller's entry does not accumulate forever in memory — this relay has no database and
// no eviction policy beyond this.
const idleLimiterTTL = 48 * time.Hour

// keyedLimiter is one rate-limit scope (e.g. "alert pushes per ticket"), holding one token
// bucket per key. It exists because golang.org/x/time/rate.Limiter is scoped to a single
// caller, and this relay needs independent buckets per ticket and per source IP.
type keyedLimiter struct {
	mu       sync.Mutex
	limiters map[string]*limiterEntry
	r        rate.Limit
	burst    int
	// retryAfter is the value reported in a 429's retry_after_seconds: the time for one token
	// to regenerate, rounded up. An approximation — the bucket may refill sooner if it was only
	// partially drained — but never too short an amount to wait.
	retryAfter time.Duration
}

type limiterEntry struct {
	limiter  *rate.Limiter
	lastUsed time.Time
}

// newKeyedLimiter builds a scope allowing perWindow events per window, refilling continuously,
// with up to burst allowed at once.
func newKeyedLimiter(perWindow int, window time.Duration, burst int) *keyedLimiter {
	return &keyedLimiter{
		limiters: make(map[string]*limiterEntry),
		r:        rate.Limit(float64(perWindow) / window.Seconds()),
		burst:    burst,

		retryAfter: durationPerToken(perWindow, window),
	}
}

// Allow reports whether key may act now, creating its bucket on first use.
func (k *keyedLimiter) Allow(key string, now time.Time) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	e, ok := k.limiters[key]
	if !ok {
		e = &limiterEntry{limiter: rate.NewLimiter(k.r, k.burst)}
		k.limiters[key] = e
	}
	e.lastUsed = now
	return e.limiter.AllowN(now, 1)
}

// sweep drops any key untouched for longer than idleLimiterTTL.
func (k *keyedLimiter) sweep(now time.Time) {
	k.mu.Lock()
	defer k.mu.Unlock()
	for key, e := range k.limiters {
		if now.Sub(e.lastUsed) > idleLimiterTTL {
			delete(k.limiters, key)
		}
	}
}

// RetryAfter reports how long a caller who just tripped this scope should wait.
func (k *keyedLimiter) RetryAfter() time.Duration { return k.retryAfter }

// TicketLimits are one app's per-ticket token-bucket parameters. Burst is configurable only for
// the alert bucket, which deliberately allows fewer than a full hour's worth at once; the
// background bucket's burst is its hourly rate, i.e. "a full hour of budget up front."
type TicketLimits struct {
	AlertPerHour      int
	AlertBurst        int
	AlertPerDay       int
	BackgroundPerHour int
}

// TicketLimiters holds one app's per-ticket scopes. Each app owns its own set, so one app's
// parameters never change another's behaviour.
type TicketLimiters struct {
	Alert      *keyedLimiter
	AlertDaily *keyedLimiter
	Background *keyedLimiter
}

func NewTicketLimiters(l TicketLimits) *TicketLimiters {
	return &TicketLimiters{
		Alert:      newKeyedLimiter(l.AlertPerHour, time.Hour, l.AlertBurst),
		AlertDaily: newKeyedLimiter(l.AlertPerDay, 24*time.Hour, l.AlertPerDay),
		Background: newKeyedLimiter(l.BackgroundPerHour, time.Hour, l.BackgroundPerHour),
	}
}

// IPLimits are the per-source-IP parameters, shared by every app: an address hammering the
// endpoints is one address, whichever app it names.
type IPLimits struct {
	PushesPerHour        int
	RegistrationsPerHour int
}

type IPLimiters struct {
	Pushes        *keyedLimiter
	Registrations *keyedLimiter
}

func NewIPLimiters(l IPLimits) *IPLimiters {
	return &IPLimiters{
		Pushes:        newKeyedLimiter(l.PushesPerHour, time.Hour, l.PushesPerHour),
		Registrations: newKeyedLimiter(l.RegistrationsPerHour, time.Hour, l.RegistrationsPerHour),
	}
}

// StartSweeper runs a periodic cleanup of every given scope's idle entries until done closes.
func StartSweeper(done <-chan struct{}, interval time.Duration, scopes ...*keyedLimiter) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case now := <-ticker.C:
				for _, l := range scopes {
					l.sweep(now)
				}
			}
		}
	}()
}

func durationPerToken(perWindow int, window time.Duration) time.Duration {
	if perWindow <= 0 {
		return window
	}
	d := window / time.Duration(perWindow)
	if d < time.Second {
		return time.Second
	}
	return d
}
