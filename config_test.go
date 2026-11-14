package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const shippedDefaults = "config/config.yaml"

// minimalOverride is the smallest override that turns the shipped defaults into a valid config.
func minimalOverride(keyPath string) string {
	return `
apns:
  key_id: ABC123
  team_id: TEAM123
  key_path: ` + keyPath + `
apps:
  alpha:
    id: 1
    topic: com.example.alpha
    payload_key: al
    fallback_title: Alpha
    fallback_body: New alpha
`
}

// loadWith writes override next to a fake key file and loads it over the shipped defaults.
func loadWith(t *testing.T, override func(keyPath string) string) (Config, error) {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "AuthKey.p8")
	if err := os.WriteFile(keyPath, []byte("not a real key, just a readable file"), 0o600); err != nil {
		t.Fatalf("writing fake key file: %v", err)
	}
	overridePath := filepath.Join(dir, "override.yaml")
	if err := os.WriteFile(overridePath, []byte(override(keyPath)), 0o600); err != nil {
		t.Fatalf("writing override: %v", err)
	}
	t.Setenv("TICKET_KEYS", "1:"+strings.Repeat("ab", 32))
	return LoadConfig(shippedDefaults, overridePath)
}

func TestShippedDefaultsPlusMinimalOverrideLoad(t *testing.T) {
	cfg, err := loadWith(t, minimalOverride)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.ListenAddr != ":8080" || cfg.TicketTTL.Hours() != 90*24 {
		t.Errorf("defaults not applied: listen %q ttl %v", cfg.ListenAddr, cfg.TicketTTL)
	}
	app, ok := cfg.Apps.ByName("alpha")
	if !ok || app.ID != 1 || app.Topic != "com.example.alpha" {
		t.Fatalf("app = %+v", app)
	}
	if app.MaxBlobChars != 3072 {
		t.Errorf("MaxBlobChars = %d, want the app_limits default 3072", app.MaxBlobChars)
	}
	if cfg.Apps.Legacy() != nil {
		t.Error("legacy app set without tickets.legacy_app")
	}
}

func TestShippedDefaultsAloneAreNotAValidConfig(t *testing.T) {
	t.Setenv("TICKET_KEYS", "1:"+strings.Repeat("ab", 32))
	if _, err := LoadConfig(shippedDefaults, ""); err == nil {
		t.Error("LoadConfig(defaults only) = nil error, want the missing apns identity reported")
	}
}

func TestMissingOverrideFileIsSkipped(t *testing.T) {
	t.Setenv("TICKET_KEYS", "1:"+strings.Repeat("ab", 32))
	t.Setenv("PUSH_RELAY_APNS_KEY_ID", "k")
	_, err := LoadConfig(shippedDefaults, filepath.Join(t.TempDir(), "absent.yaml"))
	// Still invalid (no apps), but the absent file itself is not the reason.
	if err == nil || strings.Contains(err.Error(), "absent.yaml") {
		t.Errorf("error = %v, want a validation error that does not name the absent file", err)
	}
}

func TestAppOverridesOnlyTheLimitsItNames(t *testing.T) {
	cfg, err := loadWith(t, func(k string) string {
		return minimalOverride(k) + `
app_limits:
  max_blob_chars: 2000
`
	})
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if app, _ := cfg.Apps.ByName("alpha"); app.MaxBlobChars != 2000 {
		t.Errorf("override of app_limits not inherited: %d", app.MaxBlobChars)
	}

	cfg, err = loadWith(t, func(k string) string {
		return strings.Replace(minimalOverride(k), "    fallback_body: New alpha\n", "    fallback_body: New alpha\n    limits:\n      max_blob_chars: 4096\n", 1)
	})
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	app, _ := cfg.Apps.ByName("alpha")
	if app.MaxBlobChars != 4096 {
		t.Errorf("per-app limit = %d, want 4096", app.MaxBlobChars)
	}
}

func TestEnvironmentOverridesAScalar(t *testing.T) {
	t.Setenv("PUSH_RELAY_TICKETS_TTL_DAYS", "7")
	t.Setenv("PUSH_RELAY_IP_LIMITS_PUSHES_PER_HOUR", "5")
	cfg, err := loadWith(t, minimalOverride)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.TicketTTL.Hours() != 7*24 || cfg.IP.PushesPerHour != 5 {
		t.Errorf("ttl %v, ip pushes %d", cfg.TicketTTL, cfg.IP.PushesPerHour)
	}
}

func TestEnvironmentOverrideMustParse(t *testing.T) {
	t.Setenv("PUSH_RELAY_TICKETS_TTL_DAYS", "soon")
	if _, err := loadWith(t, minimalOverride); err == nil || !strings.Contains(err.Error(), "PUSH_RELAY_TICKETS_TTL_DAYS") {
		t.Errorf("error = %v, want one naming the variable", err)
	}
}

func TestServiceLinkVariablesAreIgnored(t *testing.T) {
	// Kubernetes injects these for a Service named push-relay.
	t.Setenv("PUSH_RELAY_PORT", "tcp://10.0.0.1:8080")
	t.Setenv("PUSH_RELAY_SERVICE_HOST", "10.0.0.1")
	if _, err := loadWith(t, minimalOverride); err != nil {
		t.Errorf("LoadConfig with service-link variables: %v", err)
	}
}

func TestInvalidConfigsAreRejected(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(string) string
		wantErr string
	}{
		{"unknown key", func(s string) string { return s + "\nserver:\n  listen_adr: \":1\"\n" }, "listen_adr"},
		{"no apps", func(s string) string { return strings.Split(s, "apps:")[0] }, "at least one app"},
		{"duplicate id", func(s string) string {
			return s + "    limits: {}\n  beta:\n    id: 1\n    topic: t\n    payload_key: b\n    fallback_title: B\n    fallback_body: b\n"
		}, "already used"},
		{"id zero", func(s string) string { return strings.Replace(s, "id: 1", "id: 0", 1) }, "1-255"},
		{"id too large", func(s string) string { return strings.Replace(s, "id: 1", "id: 256", 1) }, "1-255"},
		{"bad name", func(s string) string { return strings.Replace(s, "  alpha:", "  Alpha:", 1) }, "name must be"},
		{"empty topic", func(s string) string { return strings.Replace(s, "topic: com.example.alpha", `topic: ""`, 1) }, "topic is required"},
		{"aps payload key", func(s string) string { return strings.Replace(s, "payload_key: al", "payload_key: aps", 1) }, "payload_key"},
		{"unknown legacy app", func(s string) string { return s + "tickets:\n  legacy_app: ghost\n" }, "legacy_app"},
		{"zero limit", func(s string) string { return s + "app_limits:\n  alert_per_ticket_per_hour: 0\n" }, "must be positive"},
		{"bad android package", func(s string) string {
			return strings.Replace(s, "payload_key: al", "payload_key: al\n    android_package: not-a-package", 1)
		}, "android_package"},
		{"no fcm api base", func(s string) string { return s + "fcm:\n  api_base: \"\"\n" }, "fcm.api_base"},
		{"zero fcm timeout", func(s string) string { return s + "fcm:\n  send_timeout_seconds: 0\n" }, "fcm.send_timeout_seconds"},
		{"missing key file", func(s string) string { return s + "" }, "not readable"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := loadWith(t, func(k string) string {
				base := minimalOverride(k)
				if c.name == "missing key file" {
					base = strings.Replace(base, k, "/nonexistent/AuthKey.p8", 1)
				}
				return c.mutate(base)
			})
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("error = %v, want it to contain %q", err, c.wantErr)
			}
		})
	}
}

func TestTicketKeysMustBeSet(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "AuthKey.p8")
	if err := os.WriteFile(keyPath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	overridePath := filepath.Join(dir, "o.yaml")
	if err := os.WriteFile(overridePath, []byte(minimalOverride(keyPath)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TICKET_KEYS", "")
	if _, err := LoadConfig(shippedDefaults, overridePath); err == nil || !strings.Contains(err.Error(), "tickets.keys") {
		t.Errorf("error = %v, want one naming tickets.keys", err)
	}
}

func TestLegacyAppIsResolved(t *testing.T) {
	cfg, err := loadWith(t, func(k string) string { return minimalOverride(k) + "tickets:\n  legacy_app: alpha\n" })
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Apps.Legacy() == nil || cfg.Apps.Legacy().Name != "alpha" {
		t.Errorf("legacy = %+v", cfg.Apps.Legacy())
	}
}

func TestFCMIsOffByDefaultAndTheKeyPathComesFromTheEnvironment(t *testing.T) {
	cfg, err := loadWith(t, minimalOverride)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.FCMKeyPath != "" {
		t.Errorf("FCMKeyPath = %q, want empty: Android is off without a key", cfg.FCMKeyPath)
	}
	if cfg.FCMAPIBase != "https://fcm.googleapis.com" || cfg.FCMSendTimeout != 30*time.Second {
		t.Errorf("fcm defaults = %q, %v", cfg.FCMAPIBase, cfg.FCMSendTimeout)
	}

	t.Setenv("PUSH_RELAY_FCM_KEY_PATH", "/secrets/fcm/service-account.json")
	cfg, err = loadWith(t, minimalOverride)
	if err != nil || cfg.FCMKeyPath != "/secrets/fcm/service-account.json" {
		t.Errorf("FCMKeyPath = %q, err = %v", cfg.FCMKeyPath, err)
	}
}

func TestAppAndroidPackageIsOptional(t *testing.T) {
	cfg, err := loadWith(t, func(k string) string {
		return minimalOverride(k) + "    android_package: com.example.alpha\n  beta:\n    id: 2\n    topic: t\n    payload_key: b\n    fallback_title: B\n    fallback_body: b\n"
	})
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	alpha, _ := cfg.Apps.ByName("alpha")
	beta, _ := cfg.Apps.ByName("beta")
	if alpha.AndroidPackage != "com.example.alpha" || beta.AndroidPackage != "" {
		t.Errorf("android packages = %q, %q", alpha.AndroidPackage, beta.AndroidPackage)
	}
}
