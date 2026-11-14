package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/jwt"
)

const fcmScope = "https://www.googleapis.com/auth/firebase.messaging"

// maxFCMResponseBytes bounds how much of an FCM answer is read: errors are small JSON documents.
const maxFCMResponseBytes = 64 << 10

// FCMPusher is the Pusher for Android: it sends FCM HTTP v1 data messages, authenticated with
// the service-account key of the Firebase project the Android apps belong to. One project serves
// every app of the relay.
type FCMPusher struct {
	client      *http.Client
	sendURL     string
	sendTimeout time.Duration
}

// serviceAccountKey is the part of a Google service-account JSON key the sender uses.
type serviceAccountKey struct {
	ProjectID    string `json:"project_id"`
	PrivateKeyID string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
	ClientEmail  string `json:"client_email"`
	TokenURI     string `json:"token_uri"`
}

// NewFCMPusher reads the service-account key at keyPath and builds a client that fetches and
// refreshes its own OAuth tokens. apiBase is the FCM API origin; the OAuth token endpoint comes
// from the key itself. Nothing is sent to Google until the first push.
func NewFCMPusher(keyPath, apiBase string, sendTimeout time.Duration) (*FCMPusher, error) {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading FCM service-account key %q: %w", keyPath, err)
	}
	var key serviceAccountKey
	if err := json.Unmarshal(data, &key); err != nil {
		return nil, fmt.Errorf("parsing FCM service-account key %q: %w", keyPath, err)
	}
	for _, f := range []struct{ name, val string }{
		{"project_id", key.ProjectID},
		{"private_key", key.PrivateKey},
		{"client_email", key.ClientEmail},
		{"token_uri", key.TokenURI},
	} {
		if strings.TrimSpace(f.val) == "" {
			return nil, fmt.Errorf("FCM service-account key %q has no %s", keyPath, f.name)
		}
	}

	cfg := &jwt.Config{
		Email:        key.ClientEmail,
		PrivateKey:   []byte(key.PrivateKey),
		PrivateKeyID: key.PrivateKeyID,
		TokenURL:     key.TokenURI,
		Scopes:       []string{fcmScope},
	}
	// Token fetches use their own client, bounded like a send.
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{Timeout: sendTimeout})
	if err := checkPrivateKey(key.PrivateKey); err != nil {
		return nil, fmt.Errorf("FCM service-account key %q: %w", keyPath, err)
	}

	return &FCMPusher{
		client:      cfg.Client(ctx),
		sendURL:     strings.TrimSuffix(apiBase, "/") + "/v1/projects/" + key.ProjectID + "/messages:send",
		sendTimeout: sendTimeout,
	}, nil
}

// checkPrivateKey fails at start, rather than on the first push, for a key that cannot sign.
func checkPrivateKey(pemKey string) error {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return errors.New("private_key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return errors.New("private_key is not a PKCS#8 key")
	}
	if _, ok := parsed.(*rsa.PrivateKey); !ok {
		return errors.New("private_key is not an RSA key")
	}
	return nil
}

func (p *FCMPusher) Push(ctx context.Context, req PushRequest) PushOutcome {
	body, err := json.Marshal(buildFCMMessage(req))
	if err != nil {
		return PushOutcome{Status: 502, Reason: "encoding failed"}
	}

	ctx, cancel := context.WithTimeout(ctx, p.sendTimeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.sendURL, bytes.NewReader(body))
	if err != nil {
		return PushOutcome{Status: 502, Reason: "request failed"}
	}
	httpReq.Header.Set("Content-Type", "application/json")

	res, err := p.client.Do(httpReq)
	if err != nil {
		return PushOutcome{Status: 502, Reason: transportReason(err)}
	}
	defer res.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(res.Body, maxFCMResponseBytes))
	return classifyFCM(res.StatusCode, answer, res.Header.Get("Retry-After"))
}

// transportReason names a failed round trip without the error's own text, which carries the
// request URL.
func transportReason(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case strings.Contains(err.Error(), "oauth2: cannot fetch token"):
		return "credential refused"
	default:
		return "transport error"
	}
}

type fcmEnvelope struct {
	Message fcmMessage `json:"message"`
}

type fcmMessage struct {
	Token   string            `json:"token"`
	Data    map[string]string `json:"data"`
	Android fcmAndroid        `json:"android"`
}

type fcmAndroid struct {
	Priority              string `json:"priority"`
	TTL                   string `json:"ttl"`
	CollapseKey           string `json:"collapse_key,omitempty"`
	RestrictedPackageName string `json:"restricted_package_name,omitempty"`
}

// buildFCMMessage maps one push onto a data-only message restricted to the app's Android package
// — pure and separate from Push so it is tested without a network call. There is no notification
// part: the app decrypts the blob and builds the notification itself.
func buildFCMMessage(req PushRequest) fcmEnvelope {
	m := fcmMessage{
		Token: string(req.DeviceToken),
		Android: fcmAndroid{
			TTL:                   strconv.Itoa(int(req.TTL/time.Second)) + "s",
			RestrictedPackageName: req.App.AndroidPackage,
		},
	}
	switch req.Kind {
	case "alert":
		// High priority wakes the device at once and promises FCM a user-visible notification.
		// No collapse key: FCM keeps only four per device, so one per alert would drop alerts.
		m.Data = map[string]string{"type": "alert", "v": "1", "b": req.Blob}
		m.Android.Priority = "HIGH"
	case "background":
		m.Data = map[string]string{"type": "background", "v": "1"}
		m.Android.Priority = "NORMAL"
		m.Android.CollapseKey = req.CollapseID
	}
	return fcmEnvelope{Message: m}
}

type fcmAnswer struct {
	Name  string `json:"name"`
	Error struct {
		Status  string `json:"status"`
		Details []struct {
			ErrorCode       string `json:"errorCode"`
			FieldViolations []struct {
				Field string `json:"field"`
			} `json:"fieldViolations"`
		} `json:"details"`
	} `json:"error"`
}

// classifyFCM turns one FCM response into this relay's own outcome — pure and separate from Push
// so it is tested without a network call. Only answers that say the device token itself is
// permanently unusable become 410: anything that could equally be this relay's own mistake (a
// wrong project, a malformed message, a refused credential) stays a 502, so a configuration
// error cannot make servers delete their subscriptions.
func classifyFCM(statusCode int, body []byte, retryAfter string) PushOutcome {
	var a fcmAnswer
	_ = json.Unmarshal(body, &a)
	if statusCode == http.StatusOK {
		return PushOutcome{Status: 202, ApnsID: a.Name}
	}

	code := a.Error.Status
	tokenField := false
	for _, d := range a.Error.Details {
		if d.ErrorCode != "" {
			code = d.ErrorCode
		}
		for _, v := range d.FieldViolations {
			if v.Field == "message.token" {
				tokenField = true
			}
		}
	}

	switch {
	case code == "UNREGISTERED":
		return PushOutcome{Status: 410, Reason: "Unregistered"}
	case code == "SENDER_ID_MISMATCH":
		return PushOutcome{Status: 410, Reason: "DeviceTokenNotForTopic"}
	case code == "INVALID_ARGUMENT" && tokenField:
		return PushOutcome{Status: 410, Reason: "BadDeviceToken"}
	case code == "QUOTA_EXCEEDED" || statusCode == http.StatusTooManyRequests:
		return PushOutcome{Status: 429, Reason: code, RetryAfter: parseRetryAfter(retryAfter)}
	default:
		return PushOutcome{Status: 502, Reason: safeReason(code, statusCode)}
	}
}

// parseRetryAfter reads a delay in seconds; anything else, including a date, means a minute.
func parseRetryAfter(v string) time.Duration {
	if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 && n <= 3600 {
		return time.Duration(n) * time.Second
	}
	return 60 * time.Second
}

// safeReason is the code Google named when it is a plain identifier, otherwise the HTTP status —
// the reason reaches the logs, so it must never be free text of the caller's making.
func safeReason(code string, statusCode int) string {
	if code != "" && len(code) <= 40 && strings.Trim(code, "ABCDEFGHIJKLMNOPQRSTUVWXYZ_") == "" {
		return code
	}
	return "http " + strconv.Itoa(statusCode)
}
