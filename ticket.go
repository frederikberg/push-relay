package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// The first byte of every sealed ticket, so a format change can be told apart from a corrupted
// ticket rather than misparsed. Version 2 names the app the ticket belongs to and is what APNs
// tickets use; version 3 additionally names the platform and is what every other platform's
// tickets use; version 1 carries no app and exists only so tickets issued before apps existed
// keep opening (see Config.LegacyApp).
const (
	ticketVersionLegacy   byte = 0x01
	ticketVersion         byte = 0x02
	ticketVersionPlatform byte = 0x03
)

// Each version has its own AAD, so a ticket of one version never opens as the other, and a
// ciphertext produced for something else under the same AES-GCM key never opens here.
const (
	ticketAADLegacy   = "mvpr-ticket-v1"
	ticketAAD         = "pr-ticket-v2"
	ticketAADPlatform = "pr-ticket-v3"
)

// Platform is the push service a device token belongs to. The values are sealed into version 3
// tickets: never reuse or change one.
type Platform byte

const (
	PlatformAPNS Platform = 1
	PlatformFCM  Platform = 2
)

// platformNone labels metrics of requests that never resolved to a platform.
const platformNone = "none"

// String is the name used in the API, in config and as a metrics label.
func (p Platform) String() string {
	switch p {
	case PlatformAPNS:
		return "apns"
	case PlatformFCM:
		return "fcm"
	default:
		return platformNone
	}
}

// Provider names the company behind the platform's push service, for messages.
func (p Platform) Provider() string {
	if p == PlatformFCM {
		return "Google"
	}
	return "Apple"
}

// ParsePlatform resolves the API's platform name; an empty name means APNs, the only platform
// before the field existed.
func ParsePlatform(name string) (Platform, bool) {
	switch name {
	case "", "apns":
		return PlatformAPNS, true
	case "fcm":
		return PlatformFCM, true
	default:
		return 0, false
	}
}

const nonceLen = 12

// maxTicketTokenBytes bounds a token a ticket carries, whatever the platform.
const maxTicketTokenBytes = 512

// ErrInvalidTicket covers every way a ticket fails to open at all: wrong version, unknown
// signing key, or AEAD authentication failure (corrupted, truncated, or forged). These are
// deliberately indistinguishable from each other — nothing here narrows the search for a caller
// probing the endpoint.
var ErrInvalidTicket = errors.New("invalid ticket")

// ErrTicketExpired means the ticket opened and authenticated fine, but its issued_at is older
// than the configured TTL.
var ErrTicketExpired = errors.New("ticket expired")

// OpenedTicket is what a ticket carries once it has opened and authenticated.
type OpenedTicket struct {
	// App is the id of the app the ticket was issued for. Zero for a legacy (version 1) ticket,
	// which names no app: the caller resolves it through the configured legacy app. App ids are
	// 1-255, so zero never collides with a real one.
	App byte
	// Platform is the push service the token belongs to; APNs for version 1 and 2 tickets.
	Platform    Platform
	DeviceToken []byte
	IssuedAt    time.Time
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("building cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("building AEAD: %w", err)
	}
	return gcm, nil
}

// Seal encodes an app id, a platform and a device token into a ticket only the relay's own
// signing key can produce and only a relay holding a matching key can open: version || key_id ||
// nonce || AES-256-GCM(key, nonce, plaintext, aad). An APNs token is sealed as a version 2
// ticket (app_id || len(token) || token || issued_at_unix), so what iPhones hold stays the
// format it always was; any other platform as a version 3 one (app_id || platform ||
// len(token) as two bytes || token || issued_at_unix). The length prefix exists because neither
// Apple nor Google promises tokens are a fixed size.
func (tk *TicketKeys) Seal(app byte, platform Platform, deviceToken []byte, issuedAt time.Time) (string, error) {
	if app == 0 {
		return "", fmt.Errorf("app id 0 is reserved for legacy tickets")
	}
	if platform != PlatformAPNS && platform != PlatformFCM {
		return "", fmt.Errorf("unknown platform %d", platform)
	}
	if len(deviceToken) > maxTicketTokenBytes {
		return "", fmt.Errorf("device token too long: %d bytes", len(deviceToken))
	}

	if platform == PlatformAPNS {
		if len(deviceToken) > 255 {
			return "", fmt.Errorf("APNs device token too long to length-prefix in one byte: %d bytes", len(deviceToken))
		}
		plaintext := make([]byte, 0, 2+len(deviceToken)+8)
		plaintext = append(plaintext, app, byte(len(deviceToken)))
		plaintext = append(plaintext, deviceToken...)
		plaintext = binary.BigEndian.AppendUint64(plaintext, uint64(issuedAt.Unix()))
		return tk.seal(ticketVersion, ticketAAD, plaintext)
	}

	plaintext := make([]byte, 0, 4+len(deviceToken)+8)
	plaintext = append(plaintext, app, byte(platform))
	plaintext = binary.BigEndian.AppendUint16(plaintext, uint16(len(deviceToken)))
	plaintext = append(plaintext, deviceToken...)
	plaintext = binary.BigEndian.AppendUint64(plaintext, uint64(issuedAt.Unix()))
	return tk.seal(ticketVersionPlatform, ticketAADPlatform, plaintext)
}

// sealLegacy produces a version 1 ticket. The relay never issues one; tests do, to prove old
// tickets keep opening.
func (tk *TicketKeys) sealLegacy(deviceToken []byte, issuedAt time.Time) (string, error) {
	plaintext := make([]byte, 0, 1+len(deviceToken)+8)
	plaintext = append(plaintext, byte(len(deviceToken)))
	plaintext = append(plaintext, deviceToken...)
	plaintext = binary.BigEndian.AppendUint64(plaintext, uint64(issuedAt.Unix()))

	return tk.seal(ticketVersionLegacy, ticketAADLegacy, plaintext)
}

func (tk *TicketKeys) seal(version byte, aad string, plaintext []byte) (string, error) {
	gcm, err := newGCM(tk.byID[tk.signingID])
	if err != nil {
		return "", err
	}

	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, []byte(aad))

	raw := make([]byte, 0, 2+nonceLen+len(ciphertext))
	raw = append(raw, version, tk.signingID)
	raw = append(raw, nonce...)
	raw = append(raw, ciphertext...)

	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// Open recovers the app, device token and issued-at time sealed into ticket, and checks it
// against ttl. Every configured key is tried by its id byte — a rotation that adds a new signing
// key while this is still running continues to accept tickets sealed under an older one.
func (tk *TicketKeys) Open(ticket string, ttl time.Duration, now time.Time) (OpenedTicket, error) {
	// Strict: lenient decoding ignores the last character's unused bits, so one ticket would
	// open under several strings, each with its own TicketID and rate-limit bucket.
	raw, err := base64.RawURLEncoding.Strict().DecodeString(ticket)
	if err != nil {
		return OpenedTicket{}, ErrInvalidTicket
	}
	// 1 (version) + 1 (key id) + 12 (nonce) + at least 16 (GCM tag, empty plaintext case).
	if len(raw) < 2+nonceLen+16 {
		return OpenedTicket{}, ErrInvalidTicket
	}
	version := raw[0]
	var aad string
	switch version {
	case ticketVersion:
		aad = ticketAAD
	case ticketVersionPlatform:
		aad = ticketAADPlatform
	case ticketVersionLegacy:
		aad = ticketAADLegacy
	default:
		return OpenedTicket{}, ErrInvalidTicket
	}
	keyID := raw[1]
	nonce := raw[2 : 2+nonceLen]
	ciphertext := raw[2+nonceLen:]

	key, ok := tk.byID[keyID]
	if !ok {
		return OpenedTicket{}, ErrInvalidTicket
	}
	gcm, err := newGCM(key)
	if err != nil {
		return OpenedTicket{}, ErrInvalidTicket
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, []byte(aad))
	if err != nil {
		return OpenedTicket{}, ErrInvalidTicket
	}

	opened := OpenedTicket{Platform: PlatformAPNS}
	if version != ticketVersionLegacy {
		if len(plaintext) < 1 || plaintext[0] == 0 {
			return OpenedTicket{}, ErrInvalidTicket
		}
		opened.App = plaintext[0]
		plaintext = plaintext[1:]
	}
	if version == ticketVersionPlatform {
		if len(plaintext) < 1 {
			return OpenedTicket{}, ErrInvalidTicket
		}
		opened.Platform = Platform(plaintext[0])
		if opened.Platform != PlatformAPNS && opened.Platform != PlatformFCM {
			return OpenedTicket{}, ErrInvalidTicket
		}
		plaintext = plaintext[1:]
	}
	tokenLen, lenSize := 0, 1
	if version == ticketVersionPlatform {
		lenSize = 2
	}
	if len(plaintext) < lenSize {
		return OpenedTicket{}, ErrInvalidTicket
	}
	if lenSize == 2 {
		tokenLen = int(binary.BigEndian.Uint16(plaintext))
	} else {
		tokenLen = int(plaintext[0])
	}
	if len(plaintext) != lenSize+tokenLen+8 {
		return OpenedTicket{}, ErrInvalidTicket
	}
	opened.DeviceToken = plaintext[lenSize : lenSize+tokenLen]
	opened.IssuedAt = time.Unix(int64(binary.BigEndian.Uint64(plaintext[lenSize+tokenLen:])), 0).UTC()

	if now.Sub(opened.IssuedAt) > ttl {
		return OpenedTicket{}, ErrTicketExpired
	}
	return opened, nil
}

// TicketID is the only per-device identifier that ever appears in logs, metrics or rate-limit
// keys — a stable fingerprint of the ticket string itself, not of anything it encodes. Computed
// the same way regardless of whether the ticket later turns out to be valid, so it exists even
// for a ticket this relay rejects.
func TicketID(ticket string) string {
	sum := sha256.Sum256([]byte(ticket))
	return hex.EncodeToString(sum[:])[:16]
}

// ticketKeyHexLen is 64 hex characters — a 32-byte (AES-256) key.
const ticketKeyHexLen = 64

// TicketKeys holds every configured ticket-sealing key, keyed by its single-byte id, plus which
// one is current. See ParseTicketKeys for the format.
type TicketKeys struct {
	signingID byte
	byID      map[byte][]byte
}

// ParseTicketKeys parses "<id>:<64 hex>,<id>:<64 hex>,...". The first entry is the
// signing key new tickets are sealed with; every entry is tried when opening one. Dropping an
// old entry on the next deploy is how a key is retired — tickets sealed under it then fail to
// open (401 InvalidTicket), and the app re-registers.
func ParseTicketKeys(raw string) (*TicketKeys, error) {
	entries := strings.Split(raw, ",")
	tk := &TicketKeys{byID: make(map[byte][]byte, len(entries))}
	for i, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			return nil, fmt.Errorf("empty entry")
		}
		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("entry %q is not \"<id>:<64 hex>\"", entry)
		}
		idNum, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil || idNum < 0 || idNum > 255 {
			return nil, fmt.Errorf("entry %q: key id must be 0-255", entry)
		}
		id := byte(idNum)
		keyHex := strings.TrimSpace(parts[1])
		if len(keyHex) != ticketKeyHexLen {
			return nil, fmt.Errorf("entry %q: key must be %d hex characters (32 bytes), got %d", entry, ticketKeyHexLen, len(keyHex))
		}
		key, err := hex.DecodeString(keyHex)
		if err != nil {
			return nil, fmt.Errorf("entry %q: key is not valid hex: %w", entry, err)
		}
		if _, exists := tk.byID[id]; exists {
			return nil, fmt.Errorf("duplicate key id %d", id)
		}
		tk.byID[id] = key
		if i == 0 {
			tk.signingID = id
		}
	}
	if len(tk.byID) == 0 {
		return nil, fmt.Errorf("no keys configured")
	}
	return tk, nil
}
