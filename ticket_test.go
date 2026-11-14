package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

func testKeys(t *testing.T, raw string) *TicketKeys {
	t.Helper()
	tk, err := ParseTicketKeys(raw)
	if err != nil {
		t.Fatalf("ParseTicketKeys(%q): %v", raw, err)
	}
	return tk
}

func randomKeyHex(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return hex.EncodeToString(b)
}

func TestTicketSealOpenRoundTrip(t *testing.T) {
	tk := testKeys(t, "1:"+randomKeyHex(t))
	deviceToken := []byte{0xde, 0xad, 0xbe, 0xef}
	issuedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	ticket, err := tk.Seal(1, PlatformAPNS, deviceToken, issuedAt)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	opened, err := tk.Open(ticket, 90*24*time.Hour, issuedAt.Add(time.Hour))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(opened.DeviceToken) != string(deviceToken) {
		t.Errorf("device token = %x, want %x", opened.DeviceToken, deviceToken)
	}
	if !opened.IssuedAt.Equal(issuedAt) {
		t.Errorf("issuedAt = %v, want %v", opened.IssuedAt, issuedAt)
	}
	if opened.App != 1 {
		t.Errorf("app = %d, want 1", opened.App)
	}
}

func TestTicketOpenRejectsTamperedCiphertext(t *testing.T) {
	tk := testKeys(t, "1:"+randomKeyHex(t))
	ticket, err := tk.Seal(1, PlatformAPNS, []byte{0x01, 0x02}, time.Now())
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Flip a character deep in the base64 body — past the version/key-id prefix, so this
	// exercises AEAD authentication failing, not a short-circuit on the header bytes.
	tampered := []byte(ticket)
	flipAt := len(tampered) - 1
	if tampered[flipAt] == 'A' {
		tampered[flipAt] = 'B'
	} else {
		tampered[flipAt] = 'A'
	}

	if _, err := tk.Open(string(tampered), 90*24*time.Hour, time.Now()); !errors.Is(err, ErrInvalidTicket) {
		t.Errorf("Open(tampered) error = %v, want ErrInvalidTicket", err)
	}
}

func TestTicketOpenRejectsNonCanonicalEncoding(t *testing.T) {
	tk := testKeys(t, "1:"+randomKeyHex(t))
	ticket, err := tk.Seal(1, PlatformAPNS, []byte{0x01, 0x02, 0x03}, time.Now())
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if base64.RawURLEncoding.DecodedLen(len(ticket))%3 == 0 {
		t.Fatalf("sealed length leaves no unused bits in the last character; pick another token length")
	}

	// The lowest bit of the last character carries no data here, so this string decodes to
	// the same bytes under lenient decoding. It must still be rejected: TicketID hashes the
	// string, and one ticket must not have several ids.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	variant := []byte(ticket)
	last := len(variant) - 1
	variant[last] = alphabet[strings.IndexByte(alphabet, variant[last])^1]

	if _, err := tk.Open(string(variant), 90*24*time.Hour, time.Now()); !errors.Is(err, ErrInvalidTicket) {
		t.Errorf("Open(non-canonical) error = %v, want ErrInvalidTicket", err)
	}
}

func TestTicketOpenRejectsExpired(t *testing.T) {
	tk := testKeys(t, "1:"+randomKeyHex(t))
	issuedAt := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	ticket, err := tk.Seal(1, PlatformAPNS, []byte{0x01}, issuedAt)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	ttl := 90 * 24 * time.Hour
	justBeforeExpiry := issuedAt.Add(ttl - time.Minute)
	if _, err := tk.Open(ticket, ttl, justBeforeExpiry); err != nil {
		t.Fatalf("Open just before expiry: %v", err)
	}

	justAfterExpiry := issuedAt.Add(ttl + time.Minute)
	if _, err := tk.Open(ticket, ttl, justAfterExpiry); !errors.Is(err, ErrTicketExpired) {
		t.Errorf("Open(just after expiry) error = %v, want ErrTicketExpired", err)
	}
}

func TestTicketKeyRotation(t *testing.T) {
	oldKeyHex := randomKeyHex(t)
	newKeyHex := randomKeyHex(t)
	oldKeys := testKeys(t, "1:"+oldKeyHex)
	ticket, err := oldKeys.Seal(1, PlatformAPNS, []byte{0xaa}, time.Now())
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// A rotation adds a new signing key ahead of the old one. The old key is still listed, so
	// a ticket sealed under it keeps opening.
	rotated := testKeys(t, "2:"+newKeyHex+",1:"+oldKeyHex)
	if _, err := rotated.Open(ticket, 90*24*time.Hour, time.Now()); err != nil {
		t.Errorf("Open under rotated keys (old key still present): %v", err)
	}

	// A new ticket sealed after rotation is signed with the new key, id 2, and opens under a
	// config that only knows the new key.
	newTicket, err := rotated.Seal(1, PlatformAPNS, []byte{0xbb}, time.Now())
	if err != nil {
		t.Fatalf("Seal after rotation: %v", err)
	}
	newKeyOnly := testKeys(t, "2:"+newKeyHex)
	if _, err := newKeyOnly.Open(newTicket, 90*24*time.Hour, time.Now()); err != nil {
		t.Errorf("Open(newTicket) under new-key-only config: %v", err)
	}

	// Dropping the old key entirely — the documented way to retire it — makes a ticket sealed
	// under it fail to open, rather than silently still accepted.
	if _, err := newKeyOnly.Open(ticket, 90*24*time.Hour, time.Now()); !errors.Is(err, ErrInvalidTicket) {
		t.Errorf("Open(old ticket) after dropping its key = %v, want ErrInvalidTicket", err)
	}
}

func TestTicketIDIsStableAndDependsOnTheWholeTicket(t *testing.T) {
	tk := testKeys(t, "1:"+randomKeyHex(t))
	a, err := tk.Seal(1, PlatformAPNS, []byte{0x01}, time.Now())
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	b, err := tk.Seal(1, PlatformAPNS, []byte{0x02}, time.Now())
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if TicketID(a) != TicketID(a) {
		t.Error("TicketID is not stable for the same ticket")
	}
	if TicketID(a) == TicketID(b) {
		t.Error("TicketID collided for two distinct tickets")
	}
	if len(TicketID(a)) != 16 {
		t.Errorf("TicketID length = %d, want 16", len(TicketID(a)))
	}
}

func TestParseTicketKeysRejectsMalformed(t *testing.T) {
	cases := []string{
		"",
		"not-a-valid-entry",
		"1:" + strings.Repeat("a", 63),   // too short
		"1:" + strings.Repeat("a", 65),   // too long
		"1:" + strings.Repeat("zz", 32),  // not hex
		"256:" + strings.Repeat("a", 64), // id out of byte range
		"1:" + strings.Repeat("a", 64) + ",1:" + strings.Repeat("b", 64), // duplicate id
	}
	for _, c := range cases {
		if _, err := ParseTicketKeys(c); err == nil {
			t.Errorf("ParseTicketKeys(%q) = nil error, want an error", c)
		}
	}
}

func TestTicketCarriesItsApp(t *testing.T) {
	tk := testKeys(t, "1:"+randomKeyHex(t))
	for _, app := range []byte{1, 2, 255} {
		ticket, err := tk.Seal(app, PlatformAPNS, []byte{0x01, 0x02, 0x03}, time.Now())
		if err != nil {
			t.Fatalf("Seal(app %d): %v", app, err)
		}
		opened, err := tk.Open(ticket, time.Hour, time.Now())
		if err != nil {
			t.Fatalf("Open(app %d): %v", app, err)
		}
		if opened.App != app {
			t.Errorf("opened app = %d, want %d", opened.App, app)
		}
	}
}

func TestSealRefusesTheReservedAppZero(t *testing.T) {
	tk := testKeys(t, "1:"+randomKeyHex(t))
	if _, err := tk.Seal(0, PlatformAPNS, []byte{0x01}, time.Now()); err == nil {
		t.Error("Seal(app 0) = nil error, want an error")
	}
}

func TestLegacyTicketOpensWithoutAnApp(t *testing.T) {
	tk := testKeys(t, "1:"+randomKeyHex(t))
	ticket, err := tk.sealLegacy([]byte{0xca, 0xfe}, time.Now())
	if err != nil {
		t.Fatalf("sealLegacy: %v", err)
	}
	opened, err := tk.Open(ticket, time.Hour, time.Now())
	if err != nil {
		t.Fatalf("Open(legacy): %v", err)
	}
	if opened.App != 0 {
		t.Errorf("legacy ticket app = %d, want 0", opened.App)
	}
	if string(opened.DeviceToken) != string([]byte{0xca, 0xfe}) {
		t.Errorf("device token = %x", opened.DeviceToken)
	}
}

// A real version 1 ticket produced by the relay before apps existed (device token
// deadbeef01020304), sealed under the key below. If this stops opening, phones holding such tickets fail until they re-register.
func TestRealVersion1TicketStillOpens(t *testing.T) {
	const keyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	const ticket = "AQef1_jXTHofNELu9jTGVxm27YoUf17UlqJTBL76zodTozSr2HNUTOF4JOv1vt4"
	tk := testKeys(t, "7:"+keyHex)
	opened, err := tk.Open(ticket, 100*365*24*time.Hour, time.Now())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if opened.App != 0 || hex.EncodeToString(opened.DeviceToken) != "deadbeef01020304" {
		t.Errorf("opened = %+v", opened)
	}
}

func TestVersionsDoNotCrossOpen(t *testing.T) {
	tk := testKeys(t, "1:"+randomKeyHex(t))
	v2, err := tk.Seal(1, PlatformAPNS, []byte{0x01, 0x02}, time.Now())
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(v2)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Relabelling a version 2 ciphertext as version 1 must fail authentication: the AAD differs.
	raw[0] = ticketVersionLegacy
	if _, err := tk.Open(base64.RawURLEncoding.EncodeToString(raw), time.Hour, time.Now()); !errors.Is(err, ErrInvalidTicket) {
		t.Errorf("v2 ciphertext relabelled as v1: error = %v, want ErrInvalidTicket", err)
	}
}

func TestAPNSTicketsKeepTheVersion2Format(t *testing.T) {
	tk := testKeys(t, "1:"+randomKeyHex(t))
	ticket, err := tk.Seal(1, PlatformAPNS, []byte{0x01, 0x02}, time.Now())
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(ticket)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if raw[0] != ticketVersion {
		t.Errorf("APNS ticket version = %d, want %d", raw[0], ticketVersion)
	}
	opened, err := tk.Open(ticket, time.Hour, time.Now())
	if err != nil || opened.Platform != PlatformAPNS {
		t.Errorf("Open = %+v, %v; want platform apns", opened, err)
	}
}

func TestFCMTicketRoundTrip(t *testing.T) {
	tk := testKeys(t, "1:"+randomKeyHex(t))
	// Longer than one length byte can carry, so the two-byte prefix is exercised.
	token := []byte(strings.Repeat("a1:_-", 80))
	issuedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ticket, err := tk.Seal(3, PlatformFCM, token, issuedAt)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(ticket)
	if raw[0] != ticketVersionPlatform {
		t.Errorf("FCM ticket version = %d, want %d", raw[0], ticketVersionPlatform)
	}
	opened, err := tk.Open(ticket, 90*24*time.Hour, issuedAt.Add(time.Hour))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if opened.App != 3 || opened.Platform != PlatformFCM || string(opened.DeviceToken) != string(token) || !opened.IssuedAt.Equal(issuedAt) {
		t.Errorf("opened = %+v", opened)
	}
}

func TestSealRejectsUnknownPlatformAndOversizedToken(t *testing.T) {
	tk := testKeys(t, "1:"+randomKeyHex(t))
	if _, err := tk.Seal(1, Platform(9), []byte{1}, time.Now()); err == nil {
		t.Error("unknown platform sealed")
	}
	if _, err := tk.Seal(1, PlatformFCM, make([]byte, maxTicketTokenBytes+1), time.Now()); err == nil {
		t.Error("oversized FCM token sealed")
	}
	if _, err := tk.Seal(1, PlatformAPNS, make([]byte, 256), time.Now()); err == nil {
		t.Error("oversized APNS token sealed")
	}
}

func TestPlatformTicketRelabelledAsVersion2FailsToOpen(t *testing.T) {
	tk := testKeys(t, "1:"+randomKeyHex(t))
	ticket, err := tk.Seal(1, PlatformFCM, []byte("token-token-token"), time.Now())
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(ticket)
	raw[0] = ticketVersion
	if _, err := tk.Open(base64.RawURLEncoding.EncodeToString(raw), time.Hour, time.Now()); !errors.Is(err, ErrInvalidTicket) {
		t.Errorf("v3 ciphertext relabelled as v2: error = %v, want ErrInvalidTicket", err)
	}
}

// Version 3 carries a platform byte inside the authenticated plaintext; an unknown value opens
// as nothing rather than as some default platform.
func TestVersion3TicketWithUnknownPlatformIsInvalid(t *testing.T) {
	tk := testKeys(t, "1:"+randomKeyHex(t))
	plaintext := []byte{1, 9, 0, 1, 0xaa, 0, 0, 0, 0, 0, 0, 0, 0}
	ticket, err := tk.seal(ticketVersionPlatform, ticketAADPlatform, plaintext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := tk.Open(ticket, time.Hour*24*365*100, time.Now()); !errors.Is(err, ErrInvalidTicket) {
		t.Errorf("error = %v, want ErrInvalidTicket", err)
	}
}
