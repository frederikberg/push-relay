package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakePusher lets a handler test script exactly one APNs outcome without a network call.
type fakePusher struct {
	outcome PushOutcome
	calls   int
	lastReq PushRequest
}

func (f *fakePusher) Push(_ context.Context, req PushRequest) PushOutcome {
	f.calls++
	f.lastReq = req
	return f.outcome
}

const (
	alphaApp = "alpha"
	betaApp  = "beta"
)

// testApps builds two apps with distinct topics, payload keys and blob caps, so a test can tell
// which one a push was routed to. alpha is the legacy app.
func testApps(t *testing.T, limits TicketLimits, legacy bool) *Apps {
	t.Helper()
	raw := map[string]rawApp{
		alphaApp: {ID: 1, Topic: "com.example.alpha", PayloadKey: "al", FallbackTitle: "Alpha", FallbackBody: "New alpha", AndroidPackage: "com.example.alpha.android", Limits: rawAppLimitsFrom(limits, 3072)},
		betaApp:  {ID: 2, Topic: "com.example.beta", PayloadKey: "be", FallbackTitle: "Beta", FallbackBody: "New beta", Limits: rawAppLimitsFrom(limits, 100)},
	}
	legacyName := ""
	if legacy {
		legacyName = alphaApp
	}
	apps, err := buildApps(raw, legacyName)
	if err != nil {
		t.Fatalf("buildApps: %v", err)
	}
	return apps
}

func rawAppLimitsFrom(l TicketLimits, maxBlob int) rawAppLimits {
	return rawAppLimits{
		AlertPerTicketPerHour:      l.AlertPerHour,
		AlertPerTicketBurst:        l.AlertBurst,
		AlertPerTicketPerDay:       l.AlertPerDay,
		BackgroundPerTicketPerHour: l.BackgroundPerHour,
		MaxBlobChars:               maxBlob,
		MaxTrackedKeys:             l.MaxKeys,
	}
}

type serverOpts struct {
	ticket TicketLimits
	ip     IPLimits
	legacy bool
	ttl    time.Duration
	// fcm, when set, makes the relay deliver on the fcm platform too.
	fcm Pusher
}

func testServerWith(t *testing.T, pusher Pusher, o serverOpts) (*Server, *TicketKeys) {
	t.Helper()
	tk := testKeys(t, "1:"+randomKeyHex(t))
	discard := slog.New(slog.NewTextHandler(io.Discard, nil))
	ttl := o.ttl
	if ttl == 0 {
		ttl = 90 * 24 * time.Hour
	}
	pushers := map[Platform]Pusher{PlatformAPNS: pusher}
	if o.fcm != nil {
		pushers[PlatformFCM] = o.fcm
	}
	server := NewServer(testApps(t, o.ticket, o.legacy), tk, ttl, pushers, NewIPLimiters(o.ip), NewMetrics(), discard, 8192)
	return server, tk
}

func testServer(t *testing.T, pusher Pusher, ticket TicketLimits) (*Server, *TicketKeys) {
	t.Helper()
	return testServerWith(t, pusher, serverOpts{ticket: ticket, ip: generousIPLimits()})
}

func generousRateLimits() TicketLimits {
	return TicketLimits{AlertPerHour: 1000, AlertBurst: 1000, AlertPerDay: 1000, BackgroundPerHour: 1000, MaxKeys: 1000}
}

func generousIPLimits() IPLimits {
	return IPLimits{PushesPerHour: 1000, RegistrationsPerHour: 1000, MaxKeys: 1000}
}

func doJSON(t *testing.T, h http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		reader = bytes.NewReader(b)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeBody[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode response body %q: %v", rec.Body.String(), err)
	}
	return v
}

func TestRegisterHappyPath(t *testing.T) {
	server, _ := testServer(t, &fakePusher{}, generousRateLimits())

	rec := doJSON(t, server.Handler(), "POST", "/v1/register", registerRequest{App: alphaApp, ApnsToken: strings.Repeat("ab", 32)})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	resp := decodeBody[registerResponse](t, rec)
	if resp.Ticket == "" || resp.TicketID == "" || resp.ExpiresAt == "" {
		t.Errorf("incomplete response: %+v", resp)
	}
	if resp.TicketID != TicketID(resp.Ticket) {
		t.Errorf("ticket_id in response does not match TicketID(ticket)")
	}
}

func TestRegisterRejectsBadToken(t *testing.T) {
	server, _ := testServer(t, &fakePusher{}, generousRateLimits())

	cases := []string{
		"",
		"tooshort",
		strings.Repeat("g", 32),   // not hex
		strings.Repeat("a", 15),   // below minimum, odd length too
		strings.Repeat("ab", 101), // 202 chars, over maximum
		strings.Repeat("a", 17),   // odd length
	}
	for _, tok := range cases {
		rec := doJSON(t, server.Handler(), "POST", "/v1/register", registerRequest{App: alphaApp, ApnsToken: tok})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("apns_token=%q: status = %d, want 400", tok, rec.Code)
		}
	}
}

func TestRegisterIsRateLimitedPerIP(t *testing.T) {
	server, _ := testServerWith(t, &fakePusher{}, serverOpts{
		ticket: generousRateLimits(),
		ip:     IPLimits{PushesPerHour: 1000, RegistrationsPerHour: 1, MaxKeys: 1000},
	})

	first := doJSON(t, server.Handler(), "POST", "/v1/register", registerRequest{App: alphaApp, ApnsToken: strings.Repeat("ab", 32)})
	if first.Code != http.StatusOK {
		t.Fatalf("first registration: status = %d, body = %s", first.Code, first.Body.String())
	}

	second := doJSON(t, server.Handler(), "POST", "/v1/register", registerRequest{App: alphaApp, ApnsToken: strings.Repeat("cd", 32)})
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second registration: status = %d, want 429", second.Code)
	}
	body := decodeBody[retryAfterResponse](t, second)
	if body.RetryAfterSeconds <= 0 {
		t.Errorf("retry_after_seconds = %d, want > 0", body.RetryAfterSeconds)
	}
}

func registerAndGetTicket(t *testing.T, h http.Handler) string {
	t.Helper()
	rec := doJSON(t, h, "POST", "/v1/register", registerRequest{App: alphaApp, ApnsToken: strings.Repeat("ab", 32)})
	if rec.Code != http.StatusOK {
		t.Fatalf("register: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	return decodeBody[registerResponse](t, rec).Ticket
}

func TestPushAlertHappyPath(t *testing.T) {
	pusher := &fakePusher{outcome: PushOutcome{Status: 202, ApnsID: "apns-id-123"}}
	server, _ := testServer(t, pusher, generousRateLimits())
	ticket := registerAndGetTicket(t, server.Handler())

	rec := doJSON(t, server.Handler(), "POST", "/v1/push", pushRequest{
		App: alphaApp, Ticket: ticket, Type: "alert", Blob: "YWJjZA==", CollapseID: "collapse-1", TTLSeconds: 300,
	})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	resp := decodeBody[pushResponse](t, rec)
	if resp.ApnsID != "apns-id-123" {
		t.Errorf("apns_id = %q, want %q", resp.ApnsID, "apns-id-123")
	}
	if pusher.calls != 1 {
		t.Errorf("pusher called %d times, want 1", pusher.calls)
	}
	if pusher.lastReq.Kind != "alert" || pusher.lastReq.Blob != "YWJjZA==" {
		t.Errorf("pusher received %+v, want the alert request forwarded unchanged", pusher.lastReq)
	}
}

func TestPushBackgroundRejectsBlob(t *testing.T) {
	server, _ := testServer(t, &fakePusher{}, generousRateLimits())
	ticket := registerAndGetTicket(t, server.Handler())

	rec := doJSON(t, server.Handler(), "POST", "/v1/push", pushRequest{
		App: alphaApp, Ticket: ticket, Type: "background", Blob: "YWJjZA==",
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (background push must not carry a blob)", rec.Code)
	}
}

func TestPushAlertRequiresBlob(t *testing.T) {
	server, _ := testServer(t, &fakePusher{}, generousRateLimits())
	ticket := registerAndGetTicket(t, server.Handler())

	rec := doJSON(t, server.Handler(), "POST", "/v1/push", pushRequest{App: alphaApp, Ticket: ticket, Type: "alert"})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (alert push without a blob)", rec.Code)
	}
}

func TestPushRejectsOversizedBlob(t *testing.T) {
	server, _ := testServer(t, &fakePusher{}, generousRateLimits())
	ticket := registerAndGetTicket(t, server.Handler())

	rec := doJSON(t, server.Handler(), "POST", "/v1/push", pushRequest{
		App: alphaApp, Ticket: ticket, Type: "alert", Blob: strings.Repeat("A", 3073),
	})
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", rec.Code)
	}
}

func TestPushRejectsOtherMalformedFields(t *testing.T) {
	server, _ := testServer(t, &fakePusher{}, generousRateLimits())
	ticket := registerAndGetTicket(t, server.Handler())

	cases := []struct {
		name string
		req  pushRequest
	}{
		{"ticket missing", pushRequest{App: alphaApp, Type: "alert", Blob: "YWJjZA==", TTLSeconds: 60}},
		{"type unrecognized", pushRequest{App: alphaApp, Ticket: ticket, Type: "silent", Blob: "YWJjZA==", TTLSeconds: 60}},
		{"blob not valid base64", pushRequest{App: alphaApp, Ticket: ticket, Type: "alert", Blob: "not base64!!", TTLSeconds: 60}},
		{"collapse_id over 64 bytes", pushRequest{App: alphaApp, Ticket: ticket, Type: "alert", Blob: "YWJjZA==", CollapseID: strings.Repeat("x", 65), TTLSeconds: 60}},
		{"ttl_seconds negative", pushRequest{App: alphaApp, Ticket: ticket, Type: "alert", Blob: "YWJjZA==", TTLSeconds: -1}},
		{"ttl_seconds over 86400", pushRequest{App: alphaApp, Ticket: ticket, Type: "alert", Blob: "YWJjZA==", TTLSeconds: 86401}},
	}
	for _, c := range cases {
		rec := doJSON(t, server.Handler(), "POST", "/v1/push", c.req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", c.name, rec.Code)
		}
	}
}

func TestPushRejectsOversizedBody(t *testing.T) {
	server, _ := testServer(t, &fakePusher{}, generousRateLimits())
	ticket := registerAndGetTicket(t, server.Handler())

	// A collapse_id alone, padded past the server's 8 KB body cap — the cap trips on the raw
	// body size before field-level validation (which would reject this collapse_id anyway)
	// ever runs, which is the behaviour under test.
	rec := doJSON(t, server.Handler(), "POST", "/v1/push", pushRequest{
		App: alphaApp, Ticket: ticket, Type: "alert", Blob: "YWJjZA==", CollapseID: strings.Repeat("x", 8200),
	})
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", rec.Code)
	}
}

func TestPushRejectsInvalidTicket(t *testing.T) {
	server, _ := testServer(t, &fakePusher{}, generousRateLimits())

	rec := doJSON(t, server.Handler(), "POST", "/v1/push", pushRequest{
		App: alphaApp, Ticket: "not-a-real-ticket", Type: "alert", Blob: "YWJjZA==", TTLSeconds: 60,
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := decodeBody[reasonResponse](t, rec)
	if body.Reason != "InvalidTicket" {
		t.Errorf("reason = %q, want %q", body.Reason, "InvalidTicket")
	}
}

func TestPushRejectsExpiredTicket(t *testing.T) {
	server, tk := testServerWith(t, &fakePusher{}, serverOpts{ticket: generousRateLimits(), ip: generousIPLimits(), ttl: time.Hour})

	oldTicket, err := tk.Seal(1, PlatformAPNS, []byte{0x01, 0x02}, time.Now().Add(-2*time.Hour))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	rec := doJSON(t, server.Handler(), "POST", "/v1/push", pushRequest{
		App: alphaApp, Ticket: oldTicket, Type: "alert", Blob: "YWJjZA==", TTLSeconds: 60,
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := decodeBody[reasonResponse](t, rec)
	if body.Reason != "TicketExpired" {
		t.Errorf("reason = %q, want %q", body.Reason, "TicketExpired")
	}
}

func TestPushGoneDeletesNothingButReportsReason(t *testing.T) {
	pusher := &fakePusher{outcome: PushOutcome{Status: 410, Reason: "Unregistered"}}
	server, _ := testServer(t, pusher, generousRateLimits())
	ticket := registerAndGetTicket(t, server.Handler())

	rec := doJSON(t, server.Handler(), "POST", "/v1/push", pushRequest{
		App: alphaApp, Ticket: ticket, Type: "alert", Blob: "YWJjZA==", TTLSeconds: 60,
	})
	if rec.Code != http.StatusGone {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := decodeBody[reasonResponse](t, rec)
	if body.Reason != "Unregistered" {
		t.Errorf("reason = %q, want %q", body.Reason, "Unregistered")
	}
}

func TestPushUpstreamFailureBecomes502(t *testing.T) {
	pusher := &fakePusher{outcome: PushOutcome{Status: 502, Reason: "boom"}}
	server, _ := testServer(t, pusher, generousRateLimits())
	ticket := registerAndGetTicket(t, server.Handler())

	rec := doJSON(t, server.Handler(), "POST", "/v1/push", pushRequest{
		App: alphaApp, Ticket: ticket, Type: "alert", Blob: "YWJjZA==", TTLSeconds: 60,
	})
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
}

func TestPushAlertIsRateLimitedPerTicketBeforeReachingThePusher(t *testing.T) {
	rl := generousRateLimits()
	rl.AlertPerHour = 1
	rl.AlertBurst = 1
	pusher := &fakePusher{outcome: PushOutcome{Status: 202, ApnsID: "x"}}
	server, _ := testServer(t, pusher, rl)
	ticket := registerAndGetTicket(t, server.Handler())

	first := doJSON(t, server.Handler(), "POST", "/v1/push", pushRequest{App: alphaApp, Ticket: ticket, Type: "alert", Blob: "YWJjZA==", TTLSeconds: 60})
	if first.Code != http.StatusAccepted {
		t.Fatalf("first push: status = %d, body = %s", first.Code, first.Body.String())
	}

	second := doJSON(t, server.Handler(), "POST", "/v1/push", pushRequest{App: alphaApp, Ticket: ticket, Type: "alert", Blob: "YWJjZA==", TTLSeconds: 60})
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second push: status = %d, want 429", second.Code)
	}
	if pusher.calls != 1 {
		t.Errorf("pusher called %d times, want exactly 1 — the rate limit must trip before the pusher is reached", pusher.calls)
	}
}

func TestPushBackgroundBucketIsSeparateFromAlertBucket(t *testing.T) {
	rl := generousRateLimits()
	rl.AlertPerHour = 1
	rl.AlertBurst = 1
	pusher := &fakePusher{outcome: PushOutcome{Status: 202}}
	server, _ := testServer(t, pusher, rl)
	ticket := registerAndGetTicket(t, server.Handler())

	// Exhaust the alert bucket.
	doJSON(t, server.Handler(), "POST", "/v1/push", pushRequest{App: alphaApp, Ticket: ticket, Type: "alert", Blob: "YWJjZA==", TTLSeconds: 60})

	// A background push on the very same ticket is unaffected.
	rec := doJSON(t, server.Handler(), "POST", "/v1/push", pushRequest{App: alphaApp, Ticket: ticket, Type: "background", TTLSeconds: 60})
	if rec.Code != http.StatusAccepted {
		t.Errorf("background push after exhausting the alert bucket: status = %d, want 202", rec.Code)
	}
}

func TestHealthz(t *testing.T) {
	server, _ := testServer(t, &fakePusher{}, generousRateLimits())
	rec := doJSON(t, server.Handler(), "GET", "/healthz", nil)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestMetricsEndpointExposesDeclaredNames(t *testing.T) {
	// A Prometheus CounterVec only emits a metric family once at least one label combination
	// has actually been incremented, so the test drives all three counters at least once
	// (success push, successful register, one tripped rate limit) rather than asserting on an
	// untouched collector.
	rl := generousRateLimits()
	rl.AlertPerHour = 1
	rl.AlertBurst = 1
	server, _ := testServer(t, &fakePusher{outcome: PushOutcome{Status: 202}}, rl)
	h := server.Handler()

	ticket := registerAndGetTicket(t, h)
	doJSON(t, h, "POST", "/v1/push", pushRequest{App: alphaApp, Ticket: ticket, Type: "alert", Blob: "YWJjZA==", TTLSeconds: 60})
	doJSON(t, h, "POST", "/v1/push", pushRequest{App: alphaApp, Ticket: ticket, Type: "alert", Blob: "YWJjZA==", TTLSeconds: 60})

	rec := doJSON(t, server.MetricsHandler(), "GET", "/metrics", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, name := range []string{"pushrelay_push_total", "pushrelay_register_total", "pushrelay_ratelimited_total"} {
		if !strings.Contains(body, name) {
			t.Errorf("/metrics body is missing %q", name)
		}
	}
}

// --- multi-app behaviour ---

func registerFor(t *testing.T, h http.Handler, app string) string {
	t.Helper()
	rec := doJSON(t, h, "POST", "/v1/register", registerRequest{App: app, ApnsToken: strings.Repeat("ab", 32)})
	if rec.Code != http.StatusOK {
		t.Fatalf("register %s: status = %d, body = %s", app, rec.Code, rec.Body.String())
	}
	return decodeBody[registerResponse](t, rec).Ticket
}

func pushFor(h http.Handler, t *testing.T, app, ticket string) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, h, "POST", "/v1/push", pushRequest{App: app, Ticket: ticket, Type: "alert", Blob: "YWJjZA==", TTLSeconds: 60})
}

func TestPushIsRoutedToTheTicketsApp(t *testing.T) {
	pusher := &fakePusher{outcome: PushOutcome{Status: 202, ApnsID: "x"}}
	server, _ := testServer(t, pusher, generousRateLimits())
	h := server.Handler()

	for app, topic := range map[string]string{alphaApp: "com.example.alpha", betaApp: "com.example.beta"} {
		if rec := pushFor(h, t, app, registerFor(t, h, app)); rec.Code != http.StatusAccepted {
			t.Fatalf("%s: status = %d, body = %s", app, rec.Code, rec.Body.String())
		}
		if pusher.lastReq.App.Topic != topic {
			t.Errorf("%s pushed to topic %q, want %q", app, pusher.lastReq.App.Topic, topic)
		}
	}
}

func TestATicketCannotPushToAnotherApp(t *testing.T) {
	pusher := &fakePusher{outcome: PushOutcome{Status: 202}}
	server, _ := testServer(t, pusher, generousRateLimits())
	h := server.Handler()

	betaTicket := registerFor(t, h, betaApp)
	rec := pushFor(h, t, alphaApp, betaTicket)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if reason := decodeBody[reasonResponse](t, rec).Reason; reason != "InvalidTicket" {
		t.Errorf("reason = %q, want InvalidTicket", reason)
	}
	if pusher.calls != 0 {
		t.Errorf("pusher called %d times, want 0", pusher.calls)
	}
}

func TestUnknownAppIsRejected(t *testing.T) {
	server, _ := testServer(t, &fakePusher{}, generousRateLimits())
	h := server.Handler()

	if rec := doJSON(t, h, "POST", "/v1/register", registerRequest{App: "nope", ApnsToken: strings.Repeat("ab", 32)}); rec.Code != http.StatusBadRequest {
		t.Errorf("register unknown app: status = %d, want 400", rec.Code)
	}
	if rec := pushFor(h, t, "nope", "whatever"); rec.Code != http.StatusBadRequest {
		t.Errorf("push unknown app: status = %d, want 400", rec.Code)
	}
}

func TestRequestWithoutAppNeedsALegacyApp(t *testing.T) {
	strict, _ := testServer(t, &fakePusher{}, generousRateLimits())
	if rec := doJSON(t, strict.Handler(), "POST", "/v1/register", registerRequest{ApnsToken: strings.Repeat("ab", 32)}); rec.Code != http.StatusBadRequest {
		t.Errorf("register without app and no legacy app: status = %d, want 400", rec.Code)
	}

	pusher := &fakePusher{outcome: PushOutcome{Status: 202}}
	lenient, _ := testServerWith(t, pusher, serverOpts{ticket: generousRateLimits(), ip: generousIPLimits(), legacy: true})
	h := lenient.Handler()
	rec := doJSON(t, h, "POST", "/v1/register", registerRequest{ApnsToken: strings.Repeat("ab", 32)})
	if rec.Code != http.StatusOK {
		t.Fatalf("register without app: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	ticket := decodeBody[registerResponse](t, rec).Ticket
	if push := doJSON(t, h, "POST", "/v1/push", pushRequest{Ticket: ticket, Type: "alert", Blob: "YWJjZA==", TTLSeconds: 60}); push.Code != http.StatusAccepted {
		t.Fatalf("push without app: status = %d, body = %s", push.Code, push.Body.String())
	}
	if pusher.lastReq.App.Name != alphaApp {
		t.Errorf("routed to %q, want the legacy app %q", pusher.lastReq.App.Name, alphaApp)
	}
}

func TestLegacyTicketBelongsToTheLegacyApp(t *testing.T) {
	pusher := &fakePusher{outcome: PushOutcome{Status: 202}}
	server, tk := testServerWith(t, pusher, serverOpts{ticket: generousRateLimits(), ip: generousIPLimits(), legacy: true})
	h := server.Handler()

	token := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}
	v1, err := tk.sealLegacy(token, time.Now())
	if err != nil {
		t.Fatalf("sealLegacy: %v", err)
	}

	// Named explicitly or left out, a request for the legacy app accepts it.
	for _, app := range []string{"", alphaApp} {
		if rec := pushFor(h, t, app, v1); rec.Code != http.StatusAccepted {
			t.Errorf("app %q: status = %d, body = %s", app, rec.Code, rec.Body.String())
		}
	}
	if string(pusher.lastReq.DeviceToken) != string(token) {
		t.Errorf("device token = %x", pusher.lastReq.DeviceToken)
	}
	// It must not reach another app's topic.
	if rec := pushFor(h, t, betaApp, v1); rec.Code != http.StatusUnauthorized {
		t.Errorf("legacy ticket pushed to beta: status = %d, want 401", rec.Code)
	}
}

func TestLegacyTicketIsRefusedWhenNoLegacyAppIsConfigured(t *testing.T) {
	pusher := &fakePusher{outcome: PushOutcome{Status: 202}}
	server, tk := testServer(t, pusher, generousRateLimits())

	v1, err := tk.sealLegacy([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, time.Now())
	if err != nil {
		t.Fatalf("sealLegacy: %v", err)
	}
	rec := pushFor(server.Handler(), t, alphaApp, v1)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if pusher.calls != 0 {
		t.Errorf("pusher called %d times, want 0", pusher.calls)
	}
}

func TestBlobLimitIsPerApp(t *testing.T) {
	pusher := &fakePusher{outcome: PushOutcome{Status: 202}}
	server, _ := testServer(t, pusher, generousRateLimits())
	h := server.Handler()
	blob := strings.Repeat("A", 200) // over beta's cap of 100, under alpha's 3072

	for app, want := range map[string]int{alphaApp: http.StatusAccepted, betaApp: http.StatusRequestEntityTooLarge} {
		rec := doJSON(t, h, "POST", "/v1/push", pushRequest{App: app, Ticket: registerFor(t, h, app), Type: "alert", Blob: blob, TTLSeconds: 60})
		if rec.Code != want {
			t.Errorf("%s: status = %d, want %d", app, rec.Code, want)
		}
	}
}

func TestIPPushLimitIsSharedAcrossApps(t *testing.T) {
	pusher := &fakePusher{outcome: PushOutcome{Status: 202}}
	server, _ := testServerWith(t, pusher, serverOpts{
		ticket: generousRateLimits(),
		ip:     IPLimits{PushesPerHour: 1, RegistrationsPerHour: 1000, MaxKeys: 1000},
	})
	h := server.Handler()

	if rec := pushFor(h, t, alphaApp, registerFor(t, h, alphaApp)); rec.Code != http.StatusAccepted {
		t.Fatalf("first push: status = %d", rec.Code)
	}
	if rec := pushFor(h, t, betaApp, registerFor(t, h, betaApp)); rec.Code != http.StatusTooManyRequests {
		t.Errorf("second push from the same address for another app: status = %d, want 429", rec.Code)
	}
}

func TestMetricsCarryTheAppLabel(t *testing.T) {
	server, _ := testServer(t, &fakePusher{outcome: PushOutcome{Status: 202}}, generousRateLimits())
	h := server.Handler()
	pushFor(h, t, betaApp, registerFor(t, h, betaApp))

	body := doJSON(t, server.MetricsHandler(), "GET", "/metrics", nil).Body.String()
	for _, want := range []string{
		`pushrelay_register_total{app="beta",platform="apns",result="success"} 1`,
		`pushrelay_push_total{app="beta",platform="apns",result="success",type="alert"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics is missing %q", want)
		}
	}
}

// --- platforms ---

const fcmTestToken = "cZ0abc123:APA91bHdef-ghi_jkl"

func fcmServer(t *testing.T, apns, fcm *fakePusher) *Server {
	t.Helper()
	server, _ := testServerWith(t, apns, serverOpts{ticket: generousRateLimits(), ip: generousIPLimits(), fcm: fcm})
	return server
}

func registerFCM(t *testing.T, h http.Handler, app string) string {
	t.Helper()
	rec := doJSON(t, h, "POST", "/v1/register", registerRequest{App: app, Platform: "fcm", Token: fcmTestToken})
	if rec.Code != http.StatusOK {
		t.Fatalf("register fcm for %s: status = %d, body = %s", app, rec.Code, rec.Body.String())
	}
	return decodeBody[registerResponse](t, rec).Ticket
}

func TestFCMRegistrationIssuesATicketThatPushesThroughTheFCMPusher(t *testing.T) {
	apns := &fakePusher{outcome: PushOutcome{Status: 202}}
	fcm := &fakePusher{outcome: PushOutcome{Status: 202, ApnsID: "projects/p/messages/9"}}
	h := fcmServer(t, apns, fcm).Handler()

	rec := pushFor(h, t, alphaApp, registerFCM(t, h, alphaApp))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if decodeBody[pushResponse](t, rec).ApnsID != "projects/p/messages/9" {
		t.Errorf("body = %s", rec.Body.String())
	}
	if apns.calls != 0 || fcm.calls != 1 {
		t.Errorf("apns calls = %d, fcm calls = %d; want 0 and 1", apns.calls, fcm.calls)
	}
	if string(fcm.lastReq.DeviceToken) != fcmTestToken || fcm.lastReq.App.Name != alphaApp {
		t.Errorf("fcm received %+v", fcm.lastReq)
	}
}

func TestAPNSRegistrationStillGoesThroughTheAPNSPusher(t *testing.T) {
	apns := &fakePusher{outcome: PushOutcome{Status: 202}}
	fcm := &fakePusher{outcome: PushOutcome{Status: 202}}
	h := fcmServer(t, apns, fcm).Handler()

	// Both spellings of an APNs registration: the old field, and the platform form.
	old := registerFor(t, h, alphaApp)
	rec := doJSON(t, h, "POST", "/v1/register", registerRequest{App: alphaApp, Platform: "apns", Token: strings.Repeat("ab", 32)})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	for _, ticket := range []string{old, decodeBody[registerResponse](t, rec).Ticket} {
		if got := pushFor(h, t, alphaApp, ticket); got.Code != http.StatusAccepted {
			t.Fatalf("push status = %d", got.Code)
		}
	}
	if apns.calls != 2 || fcm.calls != 0 {
		t.Errorf("apns calls = %d, fcm calls = %d; want 2 and 0", apns.calls, fcm.calls)
	}
}

func TestFCMRegistrationIsRefusedWhereTheRelayCannotDeliver(t *testing.T) {
	// No FCM pusher configured.
	h, _ := testServer(t, &fakePusher{}, generousRateLimits())
	rec := doJSON(t, h.Handler(), "POST", "/v1/register", registerRequest{App: alphaApp, Platform: "fcm", Token: fcmTestToken})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("without an FCM key: status = %d, want 400", rec.Code)
	}

	// FCM configured, but beta has no Android package.
	fh := fcmServer(t, &fakePusher{}, &fakePusher{}).Handler()
	rec = doJSON(t, fh, "POST", "/v1/register", registerRequest{App: betaApp, Platform: "fcm", Token: fcmTestToken})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("app without an Android package: status = %d, want 400", rec.Code)
	}
}

func TestRegisterRejectsAmbiguousOrMalformedPlatformFields(t *testing.T) {
	h := fcmServer(t, &fakePusher{}, &fakePusher{}).Handler()
	apnsToken := strings.Repeat("ab", 32)
	cases := map[string]registerRequest{
		"unknown platform":           {App: alphaApp, Platform: "web", Token: apnsToken},
		"apns_token and token":       {App: alphaApp, Token: apnsToken, ApnsToken: apnsToken},
		"apns_token on fcm":          {App: alphaApp, Platform: "fcm", ApnsToken: fcmTestToken},
		"no token":                   {App: alphaApp, Platform: "fcm"},
		"fcm token too short":        {App: alphaApp, Platform: "fcm", Token: "abc:def"},
		"fcm token too long":         {App: alphaApp, Platform: "fcm", Token: strings.Repeat("a", maxFCMTokenLen+1)},
		"fcm token with a quote":     {App: alphaApp, Platform: "fcm", Token: `abcdefghijklmnop"}`},
		"fcm token with whitespace":  {App: alphaApp, Platform: "fcm", Token: "abcdefgh ijklmnopqrst"},
		"hex token on apns, not hex": {App: alphaApp, Platform: "apns", Token: strings.Repeat("g", 32)},
	}
	for name, req := range cases {
		if rec := doJSON(t, h, "POST", "/v1/register", req); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", name, rec.Code)
		}
	}
}

func TestFCMRegistrationAcceptsAFirebaseInstallationID(t *testing.T) {
	h := fcmServer(t, &fakePusher{}, &fakePusher{}).Handler()
	rec := doJSON(t, h, "POST", "/v1/register", registerRequest{App: alphaApp, Platform: "fcm", Token: "cX4w9-_dQkS0aBcDeFgH1x"})
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestFCMTicketCannotPushToAnotherApp(t *testing.T) {
	fcm := &fakePusher{outcome: PushOutcome{Status: 202}}
	h := fcmServer(t, &fakePusher{}, fcm).Handler()
	ticket := registerFCM(t, h, alphaApp)
	if rec := pushFor(h, t, betaApp, ticket); rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if fcm.calls != 0 {
		t.Error("the FCM pusher was reached by a ticket of another app")
	}
}

func TestFCMTicketIsRefusedOnceTheRelayStopsDeliveringToAndroid(t *testing.T) {
	fcmH := fcmServer(t, &fakePusher{}, &fakePusher{outcome: PushOutcome{Status: 202}})
	ticket := registerFCM(t, fcmH.Handler(), alphaApp)

	// The same keys, a relay without an FCM pusher.
	noFCM := NewServer(fcmH.apps, fcmH.ticketKeys, fcmH.ticketTTL, map[Platform]Pusher{PlatformAPNS: &fakePusher{}},
		NewIPLimiters(generousIPLimits()), NewMetrics(), fcmH.log, 8192)
	rec := pushFor(noFCM.Handler(), t, alphaApp, ticket)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 so the phone registers again", rec.Code)
	}
}

func TestFCMOutcomesUseTheSameStatusCodes(t *testing.T) {
	cases := []struct {
		outcome PushOutcome
		status  int
		body    string
	}{
		{PushOutcome{Status: 410, Reason: "Unregistered"}, 410, "Unregistered"},
		{PushOutcome{Status: 429, RetryAfter: 30 * time.Second}, 429, "30"},
		{PushOutcome{Status: 502, Reason: "UNAVAILABLE"}, 502, "Google"},
	}
	for _, c := range cases {
		h := fcmServer(t, &fakePusher{}, &fakePusher{outcome: c.outcome}).Handler()
		rec := pushFor(h, t, alphaApp, registerFCM(t, h, alphaApp))
		if rec.Code != c.status || !strings.Contains(rec.Body.String(), c.body) {
			t.Errorf("%+v: status = %d, body = %q", c.outcome, rec.Code, rec.Body.String())
		}
	}
}

func TestFCMTicketsShareTheTicketRateLimits(t *testing.T) {
	rl := generousRateLimits()
	rl.AlertPerHour = 1
	rl.AlertBurst = 1
	server, _ := testServerWith(t, &fakePusher{}, serverOpts{ticket: rl, ip: generousIPLimits(), fcm: &fakePusher{outcome: PushOutcome{Status: 202}}})
	h := server.Handler()
	ticket := registerFCM(t, h, alphaApp)
	if rec := pushFor(h, t, alphaApp, ticket); rec.Code != http.StatusAccepted {
		t.Fatalf("first push: status = %d", rec.Code)
	}
	if rec := pushFor(h, t, alphaApp, ticket); rec.Code != http.StatusTooManyRequests {
		t.Errorf("second push: status = %d, want 429", rec.Code)
	}
}

func TestMetricsSeparateThePlatforms(t *testing.T) {
	server := fcmServer(t, &fakePusher{}, &fakePusher{outcome: PushOutcome{Status: 202}})
	h := server.Handler()
	pushFor(h, t, alphaApp, registerFCM(t, h, alphaApp))

	body := doJSON(t, server.MetricsHandler(), "GET", "/metrics", nil).Body.String()
	for _, want := range []string{
		`pushrelay_register_total{app="alpha",platform="fcm",result="success"} 1`,
		`pushrelay_push_total{app="alpha",platform="fcm",result="success",type="alert"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics is missing %q", want)
		}
	}
}

func TestMetricsAreNotServedOnThePublicHandler(t *testing.T) {
	server, _ := testServer(t, &fakePusher{}, generousRateLimits())
	if rec := doJSON(t, server.Handler(), "GET", "/metrics", nil); rec.Code != http.StatusNotFound {
		t.Errorf("/metrics on the public handler: status = %d, want 404", rec.Code)
	}
}

func TestClientIPGroupsIPv6ByItsSlash64(t *testing.T) {
	cases := []struct{ xff, remote, want string }{
		{"203.0.113.7", "", "203.0.113.7"},
		{"203.0.113.7, 10.0.0.1", "", "203.0.113.7"},
		{"2001:db8:1:2:aaaa:bbbb:cccc:dddd", "", "2001:db8:1:2::/64"},
		{"2001:db8:1:2:1111:2222:3333:4444, 10.0.0.1", "", "2001:db8:1:2::/64"},
		{"::ffff:203.0.113.7", "", "::ffff:203.0.113.7"},
		{"", "198.51.100.9:4444", "198.51.100.9"},
		{"", "[2001:db8:5:6:7:8:9:a]:4444", "2001:db8:5:6::/64"},
		{"not an address", "", "not an address"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := clientIP(r); got != c.want {
			t.Errorf("xff %q remote %q: clientIP = %q, want %q", c.xff, c.remote, got, c.want)
		}
	}
}
