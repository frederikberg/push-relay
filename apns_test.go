package main

import (
	"encoding/json"
	"testing"
	"time"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name       string
		statusCode int
		apnsID     string
		reason     string
		wantStatus int
	}{
		{"accepted", 200, "abc-123", "", 202},
		{"explicit 410", 410, "", "Unregistered", 410},
		{"400 with a permanently-bad reason is still treated as gone", 400, "", "BadDeviceToken", 410},
		{"400 with DeviceTokenNotForTopic is gone", 400, "", "DeviceTokenNotForTopic", 410},
		{"429 from Apple becomes our 429", 429, "", "TooManyRequests", 429},
		{"an ordinary 400 with an unrelated reason is a gateway failure", 400, "", "BadCollapseId", 502},
		{"a 500 from Apple is a gateway failure", 500, "", "InternalServerError", 502},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := classify(c.statusCode, c.apnsID, c.reason)
			if got.Status != c.wantStatus {
				t.Errorf("classify(%d, _, %q).Status = %d, want %d", c.statusCode, c.reason, got.Status, c.wantStatus)
			}
		})
	}
}

func TestClassifySuccessCarriesApnsID(t *testing.T) {
	got := classify(200, "the-apns-id", "")
	if got.ApnsID != "the-apns-id" {
		t.Errorf("ApnsID = %q, want %q", got.ApnsID, "the-apns-id")
	}
}

func TestClassifyGoneCarriesReason(t *testing.T) {
	got := classify(410, "", "Unregistered")
	if got.Reason != "Unregistered" {
		t.Errorf("Reason = %q, want %q", got.Reason, "Unregistered")
	}
}

func TestClassifyRateLimitedCarriesRetryAfter(t *testing.T) {
	got := classify(429, "", "TooManyRequests")
	if got.RetryAfter <= 0 {
		t.Errorf("RetryAfter = %v, want > 0", got.RetryAfter)
	}
}

func payloadOf(t *testing.T, req PushRequest) map[string]any {
	t.Helper()
	raw, err := json.Marshal(buildNotification(req).Payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return m
}

func TestAlertUsesTheAppsTopicBannerAndPayloadKey(t *testing.T) {
	app := &App{Topic: "com.example.lios", PayloadKey: "lios", FallbackTitle: "LIOS", FallbackBody: "New item"}
	req := PushRequest{App: app, DeviceToken: []byte{0xab, 0xcd}, Kind: "alert", Blob: "YWJj", CollapseID: "c1", TTL: time.Minute}

	n := buildNotification(req)
	if n.Topic != "com.example.lios" || n.DeviceToken != "abcd" || n.CollapseID != "c1" {
		t.Errorf("notification = topic %q token %q collapse %q", n.Topic, n.DeviceToken, n.CollapseID)
	}
	if n.PushType != "alert" || n.Expiration.IsZero() {
		t.Errorf("push type %q, expiration %v", n.PushType, n.Expiration)
	}

	p := payloadOf(t, req)
	aps := p["aps"].(map[string]any)
	alert := aps["alert"].(map[string]any)
	if alert["title"] != "LIOS" || alert["body"] != "New item" {
		t.Errorf("alert = %v", alert)
	}
	if aps["mutable-content"] != float64(1) {
		t.Errorf("mutable-content = %v, want 1", aps["mutable-content"])
	}
	custom, ok := p["lios"].(map[string]any)
	if !ok || custom["b"] != "YWJj" || custom["v"] != float64(1) {
		t.Errorf("custom payload under the app's key = %v", p["lios"])
	}
	if _, leaked := p["mv"]; leaked {
		t.Error("payload carries another app's key")
	}
}

func TestBackgroundPushCarriesNoAlertAndNoCustomKey(t *testing.T) {
	app := &App{Topic: "com.example.a", PayloadKey: "a", FallbackTitle: "A", FallbackBody: "b"}
	p := payloadOf(t, PushRequest{App: app, DeviceToken: []byte{1}, Kind: "background"})
	aps := p["aps"].(map[string]any)
	if aps["content-available"] != float64(1) || aps["alert"] != nil {
		t.Errorf("aps = %v", aps)
	}
	if _, ok := p["a"]; ok {
		t.Error("background payload carries the custom key")
	}
}
