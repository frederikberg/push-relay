package main

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// envPrefix is the prefix of the environment variables that override a config scalar.
const envPrefix = "PUSH_RELAY_"

// Config is the whole configuration surface of this service. Every value must be set by the
// layers LoadConfig applies, or the process refuses to start — a relay silently running with a
// guessed APNs topic sends pushes Apple rejects for a reason nobody sees until a phone stops
// getting them.
type Config struct {
	ListenAddr   string
	MaxBodyBytes int64

	// APNs identity. Neither id is secret — the .p8 key file is the one value that is.
	APNSKeyID       string
	APNSTeamID      string
	APNSKeyPath     string
	APNSSendTimeout time.Duration

	// TicketKeys seals and opens push tickets. The first configured key is the one new tickets
	// are sealed with; every configured key is tried when opening one.
	TicketKeys *TicketKeys
	TicketTTL  time.Duration

	IP   IPLimits
	Apps *Apps
}

type rawConfig struct {
	Server struct {
		ListenAddr   string `yaml:"listen_addr"`
		MaxBodyBytes int64  `yaml:"max_body_bytes"`
	} `yaml:"server"`
	APNS struct {
		KeyID              string `yaml:"key_id"`
		TeamID             string `yaml:"team_id"`
		KeyPath            string `yaml:"key_path"`
		SendTimeoutSeconds int    `yaml:"send_timeout_seconds"`
	} `yaml:"apns"`
	Tickets struct {
		Keys      string `yaml:"keys"`
		TTLDays   int    `yaml:"ttl_days"`
		LegacyApp string `yaml:"legacy_app"`
	} `yaml:"tickets"`
	IPLimits struct {
		PushesPerHour        int `yaml:"pushes_per_hour"`
		RegistrationsPerHour int `yaml:"registrations_per_hour"`
	} `yaml:"ip_limits"`
	AppLimits rawAppLimits      `yaml:"app_limits"`
	Apps      map[string]rawApp `yaml:"apps"`
}

type rawAppLimits struct {
	AlertPerTicketPerHour      int `yaml:"alert_per_ticket_per_hour"`
	AlertPerTicketBurst        int `yaml:"alert_per_ticket_burst"`
	AlertPerTicketPerDay       int `yaml:"alert_per_ticket_per_day"`
	BackgroundPerTicketPerHour int `yaml:"background_per_ticket_per_hour"`
	MaxBlobChars               int `yaml:"max_blob_chars"`
}

type rawApp struct {
	ID            int          `yaml:"id"`
	Topic         string       `yaml:"topic"`
	PayloadKey    string       `yaml:"payload_key"`
	FallbackTitle string       `yaml:"fallback_title"`
	FallbackBody  string       `yaml:"fallback_body"`
	Limits        rawAppLimits `yaml:"limits"`
}

var (
	appNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	envRefPattern  = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)
)

// LoadConfig applies the layers in order — the defaults file, the override file when it exists,
// ${NAME} references, environment overrides — and validates the result in one place, so main
// either has a Config it can trust completely or an error naming exactly what is wrong.
func LoadConfig(defaultsPath, overridePath string) (Config, error) {
	merged, err := readYAMLMap(defaultsPath)
	if err != nil {
		return Config{}, err
	}
	if overridePath != "" {
		if _, statErr := os.Stat(overridePath); statErr == nil {
			override, err := readYAMLMap(overridePath)
			if err != nil {
				return Config{}, err
			}
			merged = mergeMaps(merged, override)
		}
	}
	expandEnvRefs(merged)
	if err := applyEnvOverrides(merged); err != nil {
		return Config{}, err
	}
	fillAppLimits(merged)

	encoded, err := yaml.Marshal(merged)
	if err != nil {
		return Config{}, fmt.Errorf("re-encoding merged config: %w", err)
	}
	// Strict, so a misspelled key fails loudly instead of leaving its default in force.
	dec := yaml.NewDecoder(bytes.NewReader(encoded))
	dec.KnownFields(true)
	var raw rawConfig
	if err := dec.Decode(&raw); err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	return buildConfig(raw)
}

func readYAMLMap(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %q: %w", path, err)
	}
	var m map[string]any
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing config %q: %w", path, err)
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

// mergeMaps overlays b on a: maps merge key by key, every other value in b replaces a's.
func mergeMaps(a, b map[string]any) map[string]any {
	out := make(map[string]any, len(a))
	for k, v := range a {
		out[k] = v
	}
	for k, bv := range b {
		if am, ok := out[k].(map[string]any); ok {
			if bm, ok := bv.(map[string]any); ok {
				out[k] = mergeMaps(am, bm)
				continue
			}
		}
		out[k] = bv
	}
	return out
}

// expandEnvRefs replaces ${NAME} inside every string value; an unset variable becomes empty,
// which validation then reports under the key that held the reference.
func expandEnvRefs(m map[string]any) {
	for k, v := range m {
		switch x := v.(type) {
		case string:
			m[k] = envRefPattern.ReplaceAllStringFunc(x, func(ref string) string {
				return os.Getenv(envRefPattern.FindStringSubmatch(ref)[1])
			})
		case map[string]any:
			expandEnvRefs(x)
		}
	}
}

// applyEnvOverrides walks every scalar outside `apps` and replaces it with the environment
// variable named after its path when that is set. Only paths that exist are read, so the many
// PUSH_RELAY_* variables Kubernetes injects for a Service of this name are never looked at.
func applyEnvOverrides(m map[string]any) error {
	var walk func(prefix string, node map[string]any) error
	walk = func(prefix string, node map[string]any) error {
		keys := make([]string, 0, len(node))
		for k := range node {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			path := prefix + "_" + strings.ToUpper(k)
			if child, ok := node[k].(map[string]any); ok {
				// Apps are keyed by free-form names, so they have no stable variable name.
				if k == "apps" && prefix == strings.TrimSuffix(envPrefix, "_") {
					continue
				}
				if err := walk(path, child); err != nil {
					return err
				}
				continue
			}
			raw := strings.TrimSpace(os.Getenv(path))
			if raw == "" {
				continue
			}
			switch node[k].(type) {
			case int:
				n, err := strconv.Atoi(raw)
				if err != nil {
					return fmt.Errorf("%s must be an integer, got %q", path, raw)
				}
				node[k] = n
			default:
				node[k] = raw
			}
		}
		return nil
	}
	return walk(strings.TrimSuffix(envPrefix, "_"), m)
}

// fillAppLimits gives every app the app_limits it does not override itself.
func fillAppLimits(m map[string]any) {
	defaults, _ := m["app_limits"].(map[string]any)
	apps, _ := m["apps"].(map[string]any)
	for name, v := range apps {
		app, ok := v.(map[string]any)
		if !ok {
			continue
		}
		own, _ := app["limits"].(map[string]any)
		if own == nil {
			own = map[string]any{}
		}
		app["limits"] = mergeMaps(defaults, own)
		apps[name] = app
	}
}

func buildConfig(raw rawConfig) (Config, error) {
	var cfg Config
	var err error

	cfg.ListenAddr = raw.Server.ListenAddr
	if cfg.ListenAddr == "" {
		return Config{}, fmt.Errorf("server.listen_addr is required")
	}
	cfg.MaxBodyBytes = raw.Server.MaxBodyBytes
	if err := positive("server.max_body_bytes", int(cfg.MaxBodyBytes)); err != nil {
		return Config{}, err
	}

	for _, f := range []struct{ name, val string }{
		{"apns.key_id", raw.APNS.KeyID},
		{"apns.team_id", raw.APNS.TeamID},
		{"apns.key_path", raw.APNS.KeyPath},
	} {
		if strings.TrimSpace(f.val) == "" {
			return Config{}, fmt.Errorf("%s is required and must not be empty", f.name)
		}
	}
	cfg.APNSKeyID, cfg.APNSTeamID, cfg.APNSKeyPath = raw.APNS.KeyID, raw.APNS.TeamID, raw.APNS.KeyPath
	if _, statErr := os.Stat(cfg.APNSKeyPath); statErr != nil {
		return Config{}, fmt.Errorf("apns.key_path %q is not readable: %w", cfg.APNSKeyPath, statErr)
	}
	if err := positive("apns.send_timeout_seconds", raw.APNS.SendTimeoutSeconds); err != nil {
		return Config{}, err
	}
	cfg.APNSSendTimeout = time.Duration(raw.APNS.SendTimeoutSeconds) * time.Second

	if strings.TrimSpace(raw.Tickets.Keys) == "" {
		return Config{}, fmt.Errorf("tickets.keys is required and must not be empty")
	}
	if cfg.TicketKeys, err = ParseTicketKeys(raw.Tickets.Keys); err != nil {
		return Config{}, fmt.Errorf("tickets.keys: %w", err)
	}
	if err := positive("tickets.ttl_days", raw.Tickets.TTLDays); err != nil {
		return Config{}, err
	}
	cfg.TicketTTL = time.Duration(raw.Tickets.TTLDays) * 24 * time.Hour

	if err := positive("ip_limits.pushes_per_hour", raw.IPLimits.PushesPerHour); err != nil {
		return Config{}, err
	}
	if err := positive("ip_limits.registrations_per_hour", raw.IPLimits.RegistrationsPerHour); err != nil {
		return Config{}, err
	}
	cfg.IP = IPLimits{PushesPerHour: raw.IPLimits.PushesPerHour, RegistrationsPerHour: raw.IPLimits.RegistrationsPerHour}

	if cfg.Apps, err = buildApps(raw.Apps, raw.Tickets.LegacyApp); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func positive(name string, v int) error {
	if v <= 0 {
		return fmt.Errorf("%s must be positive, got %d", name, v)
	}
	return nil
}
