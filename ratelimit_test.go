package main

import (
	"strconv"
	"testing"
	"time"
)

func TestKeyedLimiterTripsAtBurst(t *testing.T) {
	// 60/hour, burst 5: the first 5 calls at the same instant succeed, the 6th does not.
	kl := newKeyedLimiter(60, time.Hour, 5, 1000)
	now := time.Now()

	for i := 0; i < 5; i++ {
		if !kl.Allow("ticket-a", now) {
			t.Fatalf("call %d: Allow = false, want true (within burst)", i+1)
		}
	}
	if kl.Allow("ticket-a", now) {
		t.Error("call 6: Allow = true, want false (burst exhausted)")
	}
}

func TestKeyedLimiterBucketsAreIndependentPerKey(t *testing.T) {
	kl := newKeyedLimiter(60, time.Hour, 1, 1000)
	now := time.Now()

	if !kl.Allow("ticket-a", now) {
		t.Fatal("ticket-a's first call should succeed")
	}
	if kl.Allow("ticket-a", now) {
		t.Error("ticket-a's second call should be rate limited")
	}
	if !kl.Allow("ticket-b", now) {
		t.Error("ticket-b should have its own, untouched bucket")
	}
}

func TestKeyedLimiterRefillsOverTime(t *testing.T) {
	// 3600/hour == 1/second, burst 1: exhausted immediately, but refilled a second later.
	kl := newKeyedLimiter(3600, time.Hour, 1, 1000)
	now := time.Now()

	if !kl.Allow("ticket-a", now) {
		t.Fatal("first call should succeed")
	}
	if kl.Allow("ticket-a", now) {
		t.Fatal("immediate second call should be rate limited")
	}
	if !kl.Allow("ticket-a", now.Add(2*time.Second)) {
		t.Error("call two seconds later should have refilled")
	}
}

func TestKeyedLimiterSweepDropsOnlyIdleKeys(t *testing.T) {
	kl := newKeyedLimiter(60, time.Hour, 5, 1000)
	now := time.Now()

	kl.Allow("idle", now)
	kl.Allow("active", now)

	later := now.Add(idleLimiterTTL + time.Minute)
	kl.Allow("active", later) // touches "active" again, so it is not idle at sweep time

	kl.sweep(later)

	kl.mu.Lock()
	_, idleStillPresent := kl.limiters["idle"]
	_, activeStillPresent := kl.limiters["active"]
	kl.mu.Unlock()

	if idleStillPresent {
		t.Error("sweep left an entry untouched for longer than idleLimiterTTL")
	}
	if !activeStillPresent {
		t.Error("sweep dropped an entry that was touched recently")
	}
}

func TestTicketLimitersEnforceScopesIndependently(t *testing.T) {
	rl := NewTicketLimiters(TicketLimits{AlertPerHour: 2, AlertBurst: 2, AlertPerDay: 100, BackgroundPerHour: 1, MaxKeys: 1000})
	now := time.Now()

	if !rl.Alert.Allow("t1", now) || !rl.Alert.Allow("t1", now) {
		t.Fatal("expected two alert pushes to fit within burst 2")
	}
	if rl.Alert.Allow("t1", now) {
		t.Error("a third alert push in the same instant should trip the per-ticket bucket")
	}

	// The same ticket's background bucket is untouched by its alert bucket tripping.
	if !rl.Background.Allow("t1", now) {
		t.Error("background bucket should be independent of the alert bucket for the same ticket")
	}
}

func TestRetryAfterIsPositiveForEveryScope(t *testing.T) {
	tl := NewTicketLimiters(TicketLimits{AlertPerHour: 60, AlertBurst: 30, AlertPerDay: 500, BackgroundPerHour: 12, MaxKeys: 1000})
	il := NewIPLimiters(IPLimits{PushesPerHour: 1200, RegistrationsPerHour: 30, MaxKeys: 1000})

	for _, l := range []*keyedLimiter{tl.Alert, tl.AlertDaily, tl.Background, il.Pushes, il.Registrations} {
		if l.RetryAfter() <= 0 {
			t.Errorf("RetryAfter for a configured scope = %v, want > 0", l.RetryAfter())
		}
	}
}

func TestKeyedLimiterForgetsTheLeastRecentlyUsedPastItsCap(t *testing.T) {
	kl := newKeyedLimiter(60, time.Hour, 1, 100)
	now := time.Now()
	for i := 0; i < 1000; i++ {
		kl.Allow(strconv.Itoa(i), now.Add(time.Duration(i)*time.Second))
	}
	if n := len(kl.limiters); n > 100 {
		t.Fatalf("tracked keys = %d, want at most 100", n)
	}
	// The newest key survived, and being tracked still means being limited.
	last := now.Add(999 * time.Second)
	if kl.Allow("999", last) {
		t.Error("the most recent key lost its bucket")
	}
	if _, ok := kl.limiters["0"]; ok {
		t.Error("the oldest key was kept")
	}
}
