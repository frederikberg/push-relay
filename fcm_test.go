package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const fcmTestPackage = "com.example.alpha.android"

// fakeFCM stands in for both Google endpoints: the OAuth token endpoint and the FCM send
// endpoint. It records what the sender posted and answers sends with whatever is scripted.
type fakeFCM struct {
	*httptest.Server
	mu         sync.Mutex
	tokenCalls int
	sends      []fcmSend
	status     int
	answer     string
	retryAfter string
}

type fcmSend struct {
	path          string
	authorization string
	body          fcmEnvelope
}

func newFakeFCM(t *testing.T) *fakeFCM {
	t.Helper()
	f := &fakeFCM{status: http.StatusOK, answer: `{"name":"projects/demo/messages/0:1"}`}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.URL.Path == "/token" {
			f.tokenCalls++
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"access_token":"fake-access-token","token_type":"Bearer","expires_in":3600}`)
			return
		}
		var env fcmEnvelope
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &env)
		f.sends = append(f.sends, fcmSend{path: r.URL.Path, authorization: r.Header.Get("Authorization"), body: env})
		if f.retryAfter != "" {
			w.Header().Set("Retry-After", f.retryAfter)
		}
		w.WriteHeader(f.status)
		_, _ = io.WriteString(w, f.answer)
	}))
	t.Cleanup(f.Close)
	return f
}

// writeServiceAccountKey writes a service-account key whose token endpoint is the fake.
func writeServiceAccountKey(t *testing.T, tokenURI string) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshalling key: %v", err)
	}
	doc := map[string]string{
		"type":           "service_account",
		"project_id":     "demo",
		"private_key_id": "kid",
		"private_key":    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email":   "relay@demo.iam.gserviceaccount.com",
		"token_uri":      tokenURI,
	}
	raw, _ := json.Marshal(doc)
	path := filepath.Join(t.TempDir(), "service-account.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("writing key: %v", err)
	}
	return path
}

func newTestFCMPusher(t *testing.T, f *fakeFCM) *FCMPusher {
	t.Helper()
	p, err := NewFCMPusher(writeServiceAccountKey(t, f.URL+"/token"), f.URL, 5*time.Second)
	if err != nil {
		t.Fatalf("NewFCMPusher: %v", err)
	}
	return p
}

func fcmRequest(kind string) PushRequest {
	app := &App{Name: "alpha", AndroidPackage: fcmTestPackage}
	req := PushRequest{App: app, DeviceToken: []byte("tok:en_-123456789"), Kind: kind, CollapseID: "c1", TTL: 5 * time.Minute}
	if kind == "alert" {
		req.Blob = "YWJjZA=="
	}
	return req
}

func TestFCMAlertIsAHighPriorityDataMessageForTheAppsPackage(t *testing.T) {
	m := buildFCMMessage(fcmRequest("alert")).Message
	if m.Token != "tok:en_-123456789" {
		t.Errorf("token = %q", m.Token)
	}
	if m.Data["type"] != "alert" || m.Data["v"] != "1" || m.Data["b"] != "YWJjZA==" || len(m.Data) != 3 {
		t.Errorf("data = %v", m.Data)
	}
	a := m.Android
	if a.Priority != "HIGH" || a.TTL != "300s" || a.RestrictedPackageName != fcmTestPackage {
		t.Errorf("android = %+v", a)
	}
	if a.CollapseKey != "" {
		t.Errorf("an alert carries collapse key %q; FCM keeps four per device, so alerts must not", a.CollapseKey)
	}
}

func TestFCMBackgroundIsANormalPriorityDataMessageThatCollapses(t *testing.T) {
	m := buildFCMMessage(fcmRequest("background")).Message
	if m.Data["type"] != "background" || len(m.Data) != 2 {
		t.Errorf("data = %v", m.Data)
	}
	if m.Android.Priority != "NORMAL" || m.Android.CollapseKey != "c1" {
		t.Errorf("android = %+v", m.Android)
	}
}

func TestFCMMessageHasNoNotificationPart(t *testing.T) {
	raw, err := json.Marshal(buildFCMMessage(fcmRequest("alert")))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "notification") {
		t.Errorf("message carries a notification part: %s", raw)
	}
}

func TestFCMZeroTTLIsSentAsZeroSeconds(t *testing.T) {
	req := fcmRequest("alert")
	req.TTL = 0
	if got := buildFCMMessage(req).Message.Android.TTL; got != "0s" {
		t.Errorf("ttl = %q, want 0s", got)
	}
}

func TestFCMPushAuthenticatesAndPostsToTheProjectEndpoint(t *testing.T) {
	f := newFakeFCM(t)
	p := newTestFCMPusher(t, f)

	for i := 0; i < 2; i++ {
		out := p.Push(context.Background(), fcmRequest("alert"))
		if out.Status != 202 || out.ApnsID != "projects/demo/messages/0:1" {
			t.Fatalf("outcome = %+v", out)
		}
	}
	if len(f.sends) != 2 {
		t.Fatalf("sends = %d, want 2", len(f.sends))
	}
	s := f.sends[0]
	if s.path != "/v1/projects/demo/messages:send" {
		t.Errorf("path = %q", s.path)
	}
	if s.authorization != "Bearer fake-access-token" {
		t.Errorf("authorization = %q", s.authorization)
	}
	if s.body.Message.Token != "tok:en_-123456789" {
		t.Errorf("token = %q", s.body.Message.Token)
	}
	if f.tokenCalls != 1 {
		t.Errorf("token endpoint called %d times, want 1: the access token is reused", f.tokenCalls)
	}
}

func TestClassifyFCM(t *testing.T) {
	unregistered := `{"error":{"code":404,"status":"NOT_FOUND","details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"UNREGISTERED"}]}}`
	senderMismatch := `{"error":{"code":403,"status":"PERMISSION_DENIED","details":[{"errorCode":"SENDER_ID_MISMATCH"}]}}`
	badToken := `{"error":{"code":400,"status":"INVALID_ARGUMENT","details":[{"@type":"type.googleapis.com/google.rpc.BadRequest","fieldViolations":[{"field":"message.token"}]}]}}`
	badOther := `{"error":{"code":400,"status":"INVALID_ARGUMENT","details":[{"fieldViolations":[{"field":"message.android.ttl"}]}]}}`
	quota := `{"error":{"code":429,"status":"RESOURCE_EXHAUSTED","details":[{"errorCode":"QUOTA_EXCEEDED"}]}}`
	cases := []struct {
		name       string
		status     int
		body       string
		retryAfter string
		want       PushOutcome
	}{
		{"accepted", 200, `{"name":"projects/p/messages/1"}`, "", PushOutcome{Status: 202, ApnsID: "projects/p/messages/1"}},
		{"unregistered", 404, unregistered, "", PushOutcome{Status: 410, Reason: "Unregistered"}},
		{"another sender", 403, senderMismatch, "", PushOutcome{Status: 410, Reason: "DeviceTokenNotForTopic"}},
		{"malformed token", 400, badToken, "", PushOutcome{Status: 410, Reason: "BadDeviceToken"}},
		{"other bad argument is our bug, not the device's", 400, badOther, "", PushOutcome{Status: 502, Reason: "INVALID_ARGUMENT"}},
		{"unknown project is not a dead device", 404, `{"error":{"code":404,"status":"NOT_FOUND"}}`, "", PushOutcome{Status: 502, Reason: "NOT_FOUND"}},
		{"quota", 429, quota, "120", PushOutcome{Status: 429, Reason: "QUOTA_EXCEEDED", RetryAfter: 120 * time.Second}},
		{"quota without hint", 429, quota, "", PushOutcome{Status: 429, Reason: "QUOTA_EXCEEDED", RetryAfter: 60 * time.Second}},
		{"quota with a date hint", 429, quota, "Wed, 21 Oct 2026 07:28:00 GMT", PushOutcome{Status: 429, Reason: "QUOTA_EXCEEDED", RetryAfter: 60 * time.Second}},
		{"unavailable", 503, `{"error":{"code":503,"status":"UNAVAILABLE"}}`, "", PushOutcome{Status: 502, Reason: "UNAVAILABLE"}},
		{"refused credential", 401, `{"error":{"code":401,"status":"UNAUTHENTICATED"}}`, "", PushOutcome{Status: 502, Reason: "UNAUTHENTICATED"}},
		{"not json", 500, "<html>oops</html>", "", PushOutcome{Status: 502, Reason: "http 500"}},
		{"free text status is not echoed", 500, `{"error":{"status":"tok:en leaked"}}`, "", PushOutcome{Status: 502, Reason: "http 500"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyFCM(c.status, []byte(c.body), c.retryAfter); got != c.want {
				t.Errorf("classifyFCM = %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestFCMPushMapsAnUnregisteredTokenTo410(t *testing.T) {
	f := newFakeFCM(t)
	f.status = 404
	f.answer = `{"error":{"code":404,"status":"NOT_FOUND","details":[{"errorCode":"UNREGISTERED"}]}}`
	out := newTestFCMPusher(t, f).Push(context.Background(), fcmRequest("alert"))
	if out.Status != 410 || out.Reason != "Unregistered" {
		t.Errorf("outcome = %+v", out)
	}
}

func TestFCMPushReportsAnUnreachableEndpointWithoutItsURL(t *testing.T) {
	f := newFakeFCM(t)
	p := newTestFCMPusher(t, f)
	f.Close()
	out := p.Push(context.Background(), fcmRequest("alert"))
	if out.Status != 502 || strings.Contains(out.Reason, "http") || strings.Contains(out.Reason, f.URL) {
		t.Errorf("outcome = %+v, want a 502 whose reason names no URL", out)
	}
}

func TestNewFCMPusherRejectsAnUnusableKey(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := map[string]string{
		"missing file":   filepath.Join(dir, "absent.json"),
		"not json":       write("a.json", "nope"),
		"no project":     write("b.json", `{"private_key":"x","client_email":"e","token_uri":"u"}`),
		"key is not PEM": write("c.json", `{"project_id":"p","private_key":"x","client_email":"e","token_uri":"u"}`),
	}
	for name, path := range cases {
		if _, err := NewFCMPusher(path, "https://fcm.example", time.Second); err == nil {
			t.Errorf("%s: NewFCMPusher = nil error", name)
		}
	}
}
