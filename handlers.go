package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	minApnsTokenHexLen = 16
	maxApnsTokenHexLen = 200
	minFCMTokenLen     = 16
	maxFCMTokenLen     = 512
	maxCollapseIDBytes = 64
	minTTLSeconds      = 0
	maxTTLSeconds      = 86400
)

// appNone labels metrics of requests that never resolved to an app.
const appNone = "none"

// Server holds everything an HTTP handler needs: the apps, the ticket keys, the rate limiters,
// one pusher per platform the relay delivers on, and nothing else — there is no store, because this relay keeps none.
type Server struct {
	apps         *Apps
	ticketKeys   *TicketKeys
	ticketTTL    time.Duration
	pushers      map[Platform]Pusher
	ip           *IPLimiters
	metrics      *Metrics
	log          *slog.Logger
	maxBodyBytes int64
	now          func() time.Time
}

func NewServer(apps *Apps, ticketKeys *TicketKeys, ticketTTL time.Duration, pushers map[Platform]Pusher, ip *IPLimiters, metrics *Metrics, log *slog.Logger, maxBodyBytes int64) *Server {
	return &Server{
		apps:         apps,
		ticketKeys:   ticketKeys,
		ticketTTL:    ticketTTL,
		pushers:      pushers,
		ip:           ip,
		metrics:      metrics,
		log:          log,
		maxBodyBytes: maxBodyBytes,
		now:          time.Now,
	}
}

// resolveApp turns the request's `app` field into an app. An empty field means the legacy app,
// when one is configured: that is how requests from builds that predate apps keep working.
func (s *Server) resolveApp(name string) (*App, error) {
	if name == "" {
		if legacy := s.apps.Legacy(); legacy != nil {
			return legacy, nil
		}
		return nil, errBadRequest("app is required")
	}
	app, ok := s.apps.ByName(name)
	if !ok {
		return nil, errBadRequest("unknown app")
	}
	return app, nil
}

// writeStatusError answers a validation failure with the status it carries.
func writeStatusError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	var se statusError
	if errors.As(err, &se) {
		status = se.status
	}
	http.Error(w, err.Error(), status)
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/register", s.handleRegister)
	mux.HandleFunc("POST /v1/push", s.handlePush)
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	return mux
}

// MetricsHandler serves the Prometheus series. It is a separate handler for a separate listener:
// nothing on the public one exposes it.
func (s *Server) MetricsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(s.metrics.registry, promhttp.HandlerOpts{}))
	return mux
}

// --- /v1/register ---

type registerRequest struct {
	App      string `json:"app"`
	Platform string `json:"platform"`
	Token    string `json:"token"`
	// ApnsToken is the pre-platform spelling of Token, valid for the apns platform only.
	ApnsToken string `json:"apns_token"`
}

type registerResponse struct {
	Ticket    string `json:"ticket"`
	TicketID  string `json:"ticket_id"`
	ExpiresAt string `json:"expires_at"`
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	now := s.now()

	if !s.ip.Registrations.Allow(ip, now) {
		s.metrics.RateLimitedTotal.WithLabelValues(appNone, "ip_register").Inc()
		s.metrics.RegisterTotal.WithLabelValues(appNone, platformNone, "ratelimited").Inc()
		writeRetryAfter(w, s.ip.Registrations.RetryAfter())
		return
	}

	req, err := decodeJSONBody[registerRequest](w, r, s.maxBodyBytes)
	if err != nil {
		s.metrics.RegisterTotal.WithLabelValues(appNone, platformNone, "invalid").Inc()
		writeDecodeError(w, err)
		return
	}
	app, err := s.resolveApp(req.App)
	if err != nil {
		s.metrics.RegisterTotal.WithLabelValues(appNone, platformNone, "invalid").Inc()
		writeStatusError(w, err)
		return
	}
	platform, rawToken, err := registrationToken(req)
	if err != nil {
		s.metrics.RegisterTotal.WithLabelValues(app.Name, platformNone, "invalid").Inc()
		writeStatusError(w, err)
		return
	}
	// A platform the relay cannot deliver on yields no ticket: it would never work.
	if _, ok := s.pushers[platform]; !ok || (platform == PlatformFCM && app.AndroidPackage == "") {
		s.metrics.RegisterTotal.WithLabelValues(app.Name, platform.String(), "invalid").Inc()
		http.Error(w, "platform is not available for this app", http.StatusBadRequest)
		return
	}
	deviceToken, err := decodeToken(platform, rawToken)
	if err != nil {
		s.metrics.RegisterTotal.WithLabelValues(app.Name, platform.String(), "invalid").Inc()
		writeStatusError(w, err)
		return
	}

	ticket, err := s.ticketKeys.Seal(app.ID, platform, deviceToken, now)
	if err != nil {
		s.log.Error("register: could not seal ticket", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.metrics.RegisterTotal.WithLabelValues(app.Name, platform.String(), "success").Inc()
	s.log.Info("register", "app", app.Name, "platform", platform.String(), "ticket_id", TicketID(ticket), "result", "success")

	writeJSON(w, http.StatusOK, registerResponse{
		Ticket:    ticket,
		TicketID:  TicketID(ticket),
		ExpiresAt: now.Add(s.ticketTTL).UTC().Format(time.RFC3339),
	})
}

// --- /v1/push ---

type pushRequest struct {
	App        string `json:"app"`
	Ticket     string `json:"ticket"`
	Type       string `json:"type"`
	Blob       string `json:"blob"`
	CollapseID string `json:"collapse_id"`
	TTLSeconds int    `json:"ttl_seconds"`
}

type pushResponse struct {
	ApnsID string `json:"apns_id"`
}

type reasonResponse struct {
	Reason string `json:"reason"`
}

type retryAfterResponse struct {
	RetryAfterSeconds int `json:"retry_after_seconds"`
}

func (s *Server) handlePush(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	now := s.now()

	req, err := decodeJSONBody[pushRequest](w, r, s.maxBodyBytes)
	if err != nil {
		writeDecodeError(w, err)
		return
	}
	app, err := s.resolveApp(req.App)
	if err != nil {
		writeStatusError(w, err)
		return
	}
	if err := validatePushRequest(req, app); err != nil {
		writeStatusError(w, err)
		return
	}

	var ticketID string
	if req.Ticket != "" {
		ticketID = TicketID(req.Ticket)
	}
	opened, err := s.ticketKeys.Open(req.Ticket, s.ticketTTL, now)
	if err != nil {
		reason := "InvalidTicket"
		if errors.Is(err, ErrTicketExpired) {
			reason = "TicketExpired"
		}
		s.metrics.PushTotal.WithLabelValues(app.Name, platformNone, req.Type, "invalid_ticket").Inc()
		s.log.Info("push", "app", app.Name, "ticket_id", ticketID, "result", "invalid_ticket")
		writeJSON(w, http.StatusUnauthorized, reasonResponse{Reason: reason})
		return
	}
	// A version 1 ticket names no app: it belongs to the legacy app. Either way the ticket's app
	// must be the one the request names, so a ticket issued for one app can never push to
	// another app's topic. The caller sees the same answer as for an unopenable ticket.
	ticketApp := s.apps.Legacy()
	if opened.App != 0 {
		ticketApp, _ = s.apps.ByID(opened.App)
	}
	if ticketApp != app {
		s.metrics.PushTotal.WithLabelValues(app.Name, opened.Platform.String(), req.Type, "app_mismatch").Inc()
		s.log.Info("push", "app", app.Name, "platform", opened.Platform.String(), "ticket_id", ticketID, "result", "app_mismatch")
		writeJSON(w, http.StatusUnauthorized, reasonResponse{Reason: "InvalidTicket"})
		return
	}

	if !s.ip.Pushes.Allow(ip, now) {
		s.respondRateLimited(w, app, opened.Platform, "ip_push", req.Type, ticketID, s.ip.Pushes)
		return
	}

	limiters := app.Limiters
	if req.Type == "alert" {
		if !limiters.Alert.Allow(ticketID, now) {
			s.respondRateLimited(w, app, opened.Platform, "ticket_alert", req.Type, ticketID, limiters.Alert)
			return
		}
		if !limiters.AlertDaily.Allow(ticketID, now) {
			s.respondRateLimited(w, app, opened.Platform, "ticket_alert_daily", req.Type, ticketID, limiters.AlertDaily)
			return
		}
	} else {
		if !limiters.Background.Allow(ticketID, now) {
			s.respondRateLimited(w, app, opened.Platform, "ticket_background", req.Type, ticketID, limiters.Background)
			return
		}
	}

	pusher, ok := s.pushers[opened.Platform]
	if !ok || (opened.Platform == PlatformFCM && app.AndroidPackage == "") {
		// The ticket is genuine but this relay no longer delivers on its platform for this app:
		// the phone registers again, and that is refused with the reason.
		s.metrics.PushTotal.WithLabelValues(app.Name, opened.Platform.String(), req.Type, "invalid_ticket").Inc()
		s.log.Info("push", "app", app.Name, "platform", opened.Platform.String(), "ticket_id", ticketID, "result", "platform_unavailable")
		writeJSON(w, http.StatusUnauthorized, reasonResponse{Reason: "InvalidTicket"})
		return
	}
	outcome := pusher.Push(r.Context(), PushRequest{
		App:         app,
		DeviceToken: opened.DeviceToken,
		Kind:        req.Type,
		Blob:        req.Blob,
		CollapseID:  req.CollapseID,
		TTL:         time.Duration(req.TTLSeconds) * time.Second,
	})

	result := resultLabel(outcome.Status)
	s.metrics.PushTotal.WithLabelValues(app.Name, opened.Platform.String(), req.Type, result).Inc()
	if outcome.Status == 502 && outcome.Reason != "" {
		// Pushers only ever put a short, device-free reason here (never an error's own text).
		s.log.Info("push", "app", app.Name, "platform", opened.Platform.String(), "ticket_id", ticketID, "result", result, "reason", outcome.Reason)
	} else {
		s.log.Info("push", "app", app.Name, "platform", opened.Platform.String(), "ticket_id", ticketID, "result", result)
	}

	switch outcome.Status {
	case 202:
		writeJSON(w, http.StatusAccepted, pushResponse{ApnsID: outcome.ApnsID})
	case 410:
		writeJSON(w, http.StatusGone, reasonResponse{Reason: outcome.Reason})
	case 429:
		writeRetryAfter(w, outcome.RetryAfter)
	default:
		http.Error(w, "push to "+opened.Platform.Provider()+" failed", http.StatusBadGateway)
	}
}

func (s *Server) respondRateLimited(w http.ResponseWriter, app *App, platform Platform, scope, pushType, ticketID string, limiter *keyedLimiter) {
	s.metrics.RateLimitedTotal.WithLabelValues(app.Name, scope).Inc()
	s.metrics.PushTotal.WithLabelValues(app.Name, platform.String(), pushType, "ratelimited").Inc()
	s.log.Info("push", "app", app.Name, "platform", platform.String(), "ticket_id", ticketID, "result", "ratelimited", "scope", scope)
	writeRetryAfter(w, limiter.RetryAfter())
}

func resultLabel(status int) string {
	switch status {
	case 202:
		return "success"
	case 410:
		return "gone"
	case 429:
		return "ratelimited"
	default:
		return "failure"
	}
}

func validatePushRequest(req pushRequest, app *App) error {
	if req.Ticket == "" {
		return errBadRequest("ticket is required")
	}
	if req.Type != "alert" && req.Type != "background" {
		return errBadRequest(`type must be "alert" or "background"`)
	}
	if req.Type == "alert" {
		if req.Blob == "" {
			return errBadRequest("blob is required when type is \"alert\"")
		}
	} else if req.Blob != "" {
		return errBadRequest("blob must be absent when type is \"background\"")
	}
	if len(req.Blob) > app.MaxBlobChars {
		return errPayloadTooLarge("blob exceeds the size limit")
	}
	if req.Blob != "" {
		if _, err := base64.StdEncoding.DecodeString(req.Blob); err != nil {
			return errBadRequest("blob is not valid base64")
		}
	}
	if len([]byte(req.CollapseID)) > maxCollapseIDBytes {
		return errBadRequest("collapse_id exceeds 64 bytes")
	}
	if req.TTLSeconds < minTTLSeconds || req.TTLSeconds > maxTTLSeconds {
		return errBadRequest("ttl_seconds must be between 0 and 86400")
	}
	return nil
}

// --- shared plumbing ---

// statusError carries the HTTP status a validation failure should produce, so
// validatePushRequest can distinguish 400 (malformed) from 413 (too large) without the caller
// re-deriving it.
type statusError struct {
	status int
	msg    string
}

func (e statusError) Error() string { return e.msg }

func errBadRequest(msg string) error { return statusError{status: http.StatusBadRequest, msg: msg} }
func errPayloadTooLarge(msg string) error {
	return statusError{status: http.StatusRequestEntityTooLarge, msg: msg}
}

func decodeJSONBody[T any](w http.ResponseWriter, r *http.Request, maxBytes int64) (T, error) {
	var v T
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&v); err != nil {
		return v, err
	}
	return v, nil
}

func writeDecodeError(w http.ResponseWriter, err error) {
	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	http.Error(w, "malformed request body", http.StatusBadRequest)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeRetryAfter(w http.ResponseWriter, d time.Duration) {
	seconds := int(d.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	writeJSON(w, http.StatusTooManyRequests, retryAfterResponse{RetryAfterSeconds: seconds})
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// registrationToken resolves which platform a registration is for and the raw token it carries,
// accepting the pre-platform `apns_token` spelling for apns only.
func registrationToken(req registerRequest) (Platform, string, error) {
	platform, ok := ParsePlatform(req.Platform)
	if !ok {
		return 0, "", errBadRequest("platform must be \"apns\" or \"fcm\"")
	}
	token := req.Token
	if req.ApnsToken != "" {
		if token != "" || platform != PlatformAPNS {
			return 0, "", errBadRequest("apns_token is only valid on its own for the apns platform")
		}
		token = req.ApnsToken
	}
	return platform, token, nil
}

// decodeToken validates a registration token for its platform and returns the bytes a ticket
// seals. This endpoint has no auth in front of it, so this validation is the only thing standing
// between it and arbitrary junk being sealed into a ticket.
func decodeToken(platform Platform, raw string) ([]byte, error) {
	token := strings.TrimSpace(raw)
	if platform == PlatformFCM {
		if !isValidFCMToken(token) {
			return nil, errBadRequest("token is required and must be a 16-512 character string of letters, digits, - _ and :")
		}
		return []byte(token), nil
	}
	token = strings.ToLower(token)
	if !isValidApnsTokenHex(token) {
		return nil, errBadRequest("apns_token is required and must be a 16-200 character, even-length hex string")
	}
	deviceToken, err := hex.DecodeString(token)
	if err != nil {
		// isValidApnsTokenHex already checked this, but never trust a decode to succeed just
		// because a hand-written validator said so.
		return nil, errBadRequest("apns_token is not valid hex")
	}
	return deviceToken, nil
}

// isValidFCMToken accepts what FCM registration tokens and Firebase installation ids are made
// of — url-safe base64 characters and the colon between a token's two halves — and nothing else.
func isValidFCMToken(s string) bool {
	if len(s) < minFCMTokenLen || len(s) > maxFCMTokenLen {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-' || c == '_' || c == ':') {
			return false
		}
	}
	return true
}

// isValidApnsTokenHex accepts what an APNs device token actually looks like — an even-length hex
// string, bounded — rather than the empty "non-empty string" check a gated backend can get away
// with. This endpoint has no auth in front of it, so this validation is the only thing standing
// between it and arbitrary junk being sealed into a ticket.
func isValidApnsTokenHex(s string) bool {
	if len(s) < minApnsTokenHexLen || len(s) > maxApnsTokenHexLen || len(s)%2 != 0 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// clientIP trusts X-Forwarded-For's first entry when present. The Service this runs behind has
// no public ClusterIP of its own — every caller arrives through the ingress proxy in front of
// it, which is the one thing allowed to set this header, so there is no stranger able to spoof
// it directly against the pod. An IPv6 address is reduced to its /64, the smallest block an
// operator hands out, so one subscriber cannot mint a rate-limit bucket per address.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first := xff
		if i := strings.IndexByte(xff, ','); i >= 0 {
			first = xff[:i]
		}
		return limiterKey(strings.TrimSpace(first))
	}
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return limiterKey(host)
}

// limiterKey is the rate-limit key of a source address: IPv4 and anything unparseable as it is,
// IPv6 as its /64 prefix.
func limiterKey(addr string) string {
	ip, err := netip.ParseAddr(addr)
	if err != nil || ip.Is4() || ip.Is4In6() {
		return addr
	}
	prefix, err := ip.Prefix(64)
	if err != nil {
		return addr
	}
	return prefix.String()
}
