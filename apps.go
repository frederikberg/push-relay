package main

import (
	"fmt"
	"sort"
	"strings"
)

// App is one application the relay pushes for: its APNs topic, how its notifications look
// before the app's own extension replaces them, and its limits. An app is the only thing a
// ticket is bound to, so a ticket issued for one app can never push to another's topic.
type App struct {
	Name string
	// ID is what a ticket carries instead of the name: one byte, never reused.
	ID byte
	// Topic is the app's bundle id. APNs rejects a push whose topic does not match the token's
	// own app, so a wrong value fails loud (DeviceTokenNotForTopic) rather than reaching no one.
	Topic string
	// PayloadKey is the key under which the blob reaches the app's notification extension.
	PayloadKey string
	// FallbackTitle and FallbackBody are what Apple shows before the extension decrypts the
	// real banner — fixed configuration, never caller-supplied, since the relay never knows
	// what an alert is actually about.
	FallbackTitle string
	FallbackBody  string
	// MaxBlobChars bounds the blob field specifically, since a request can be under the body
	// cap and still carry an oversized blob.
	MaxBlobChars int
	Limiters     *TicketLimiters
}

// Apps is the set of configured apps, looked up by the name callers send and by the id a ticket
// carries.
type Apps struct {
	byName map[string]*App
	byID   map[byte]*App
	legacy *App
}

func (a *Apps) ByName(name string) (*App, bool) { app, ok := a.byName[name]; return app, ok }
func (a *Apps) ByID(id byte) (*App, bool)       { app, ok := a.byID[id]; return app, ok }

// Legacy is the app that version 1 tickets and requests without an `app` field belong to, or
// nil when the relay accepts neither.
func (a *Apps) Legacy() *App { return a.legacy }

// All returns every app, ordered by name.
func (a *Apps) All() []*App {
	out := make([]*App, 0, len(a.byName))
	for _, app := range a.byName {
		out = append(out, app)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func buildApps(raw map[string]rawApp, legacyName string) (*Apps, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("apps: at least one app is required")
	}
	apps := &Apps{byName: map[string]*App{}, byID: map[byte]*App{}}

	names := make([]string, 0, len(raw))
	for name := range raw {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		r := raw[name]
		where := "apps." + name
		if !appNamePattern.MatchString(name) {
			return nil, fmt.Errorf("%s: name must be lowercase letters, digits and -, starting with a letter, at most 32 characters", where)
		}
		if r.ID < 1 || r.ID > 255 {
			return nil, fmt.Errorf("%s.id must be 1-255, got %d", where, r.ID)
		}
		if other, taken := apps.byID[byte(r.ID)]; taken {
			return nil, fmt.Errorf("%s.id %d is already used by app %q", where, r.ID, other.Name)
		}
		for _, f := range []struct{ field, val string }{
			{"topic", r.Topic},
			{"payload_key", r.PayloadKey},
			{"fallback_title", r.FallbackTitle},
			{"fallback_body", r.FallbackBody},
		} {
			if strings.TrimSpace(f.val) == "" {
				return nil, fmt.Errorf("%s.%s is required and must not be empty", where, f.field)
			}
		}
		// "aps" is Apple's own top-level payload key; a custom key of that name would clobber the alert.
		if r.PayloadKey == "aps" {
			return nil, fmt.Errorf("%s.payload_key must not be \"aps\"", where)
		}
		l := r.Limits
		for _, f := range []struct {
			field string
			val   int
		}{
			{"alert_per_ticket_per_hour", l.AlertPerTicketPerHour},
			{"alert_per_ticket_burst", l.AlertPerTicketBurst},
			{"alert_per_ticket_per_day", l.AlertPerTicketPerDay},
			{"background_per_ticket_per_hour", l.BackgroundPerTicketPerHour},
			{"max_blob_chars", l.MaxBlobChars},
		} {
			if err := positive(where+".limits."+f.field, f.val); err != nil {
				return nil, err
			}
		}

		app := &App{
			Name:          name,
			ID:            byte(r.ID),
			Topic:         r.Topic,
			PayloadKey:    r.PayloadKey,
			FallbackTitle: r.FallbackTitle,
			FallbackBody:  r.FallbackBody,
			MaxBlobChars:  l.MaxBlobChars,
			Limiters: NewTicketLimiters(TicketLimits{
				AlertPerHour:      l.AlertPerTicketPerHour,
				AlertBurst:        l.AlertPerTicketBurst,
				AlertPerDay:       l.AlertPerTicketPerDay,
				BackgroundPerHour: l.BackgroundPerTicketPerHour,
			}),
		}
		apps.byName[name] = app
		apps.byID[app.ID] = app
	}

	if legacyName != "" {
		legacy, ok := apps.byName[legacyName]
		if !ok {
			return nil, fmt.Errorf("tickets.legacy_app %q is not a configured app", legacyName)
		}
		apps.legacy = legacy
	}
	return apps, nil
}

// Sweepable lists every per-ticket scope of every app, for the idle-entry sweeper.
func (a *Apps) Sweepable() []*keyedLimiter {
	var out []*keyedLimiter
	for _, app := range a.All() {
		out = append(out, app.Limiters.Alert, app.Limiters.AlertDaily, app.Limiters.Background)
	}
	return out
}
