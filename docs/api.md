# API

All endpoints are JSON over HTTPS. Responses whose status code is 400, 413 or 502 carry a short
plain-text message rather than a JSON body; every other response shown below is JSON.

A relay serves one or more **apps**. An app is what a caller names in the `app` field, and it
decides the APNs topic, the banner Apple shows before the app's own notification extension
replaces it, the key under which the blob reaches that extension and, for an app that also runs
on Android, its package name. Which apps a relay serves is configuration
([operations.md](operations.md)).

A relay delivers through one or two **platforms**: `apns` (iPhone, always) and `fcm` (Android
through Firebase Cloud Messaging, only when the relay was given a Firebase service-account key).
A ticket is bound to the platform its device registered on.

## Shape

- **No authentication header.** A sealed, expiring *ticket* issued by `/v1/register` is the only
  credential a caller presents. It authorizes exactly one device token of exactly one app and
  platform.
  There is no account, API key or sign-up with the relay operator: the phone registers directly.
- **Nothing is stored.** No database, no volume. A ticket is self-contained, sealed with a key
  only the relay holds. Restarting the relay invalidates nothing; dropping a signing key makes
  the tickets sealed under it fail to open, which the caller sees as an invalid ticket.
- **The relay never reads the notification content.** An alert's `blob` is opaque,
  end-to-end-encrypted by the sender for the phone's own notification extension, and forwarded to
  Apple unmodified. Everything the relay needs to route a push (type, collapse id, time-to-live)
  travels outside the blob, in plain request fields.
- **A ticket cannot cross apps.** The app is sealed into the ticket; a push naming another app is
  refused, so a ticket issued for one app can never reach another app's topic.

## Registration handshake

- A phone registers its push token with the relay directly (an APNs device token, or an FCM
  registration token): `POST /v1/register`, naming its app and platform.
- The relay returns a ticket bound to that app, platform and token, with an expiry.
- The phone hands the ticket (and a content key it generated itself, which never reaches the
  relay) to its own server.
- The server calls `POST /v1/push` with that ticket whenever it has something to deliver. The
  relay opens the ticket, recovers the token and forwards the push to Apple or Google. It never sees
  which server sent it beyond the caller's IP address, and never sees why.
- There is no unregister endpoint: a ticket stops working when it expires or its signing key is
  dropped, and a server stops pushing to a device when the phone stops refreshing its ticket
  there.

## `POST /v1/register`

Request:

```json
{"app": "<app name>", "platform": "apns", "token": "<platform token>"}
```

- `platform` is `"apns"` or `"fcm"`; left out it means `"apns"`.
- `token` for `apns` is a hex device token, 16-200 characters, even length. For `fcm` it is the
  registration token (or Firebase installation id) the Firebase SDK hands the app: 16-512
  characters of letters, digits, `-`, `_` and `:`. The relay treats it as opaque.
- `apns_token` is accepted in place of `token` for `apns` registrations (the form every build
  before FCM support sends); it must not be combined with `token` or with another platform.
- `app` may be left out only when the relay is configured with a legacy app (see
  [operations.md](operations.md)); it then means that app.

Response `200`:

```json
{"ticket": "<opaque string>", "ticket_id": "<16 hex characters>", "expires_at": "<RFC3339 UTC>"}
```

- `ticket` is opaque to every caller: store and forward it verbatim, never parse it.
- `ticket_id` is a stable, non-secret fingerprint of the ticket. It is the only per-device value
  in the relay's logs and metrics, and is safe to log on the calling side too.
- `expires_at` is when the ticket stops working. Register again well before then; treat a ticket
  nearing expiry, or a `401 TicketExpired` from a push, as "register again".

Errors:

- `400` — `app` unknown or (without a legacy app) missing, `platform` unknown, the token missing,
  malformed or sent in two fields, or the platform not available: `fcm` on a relay without a
  Firebase key, or for an app that has no Android package.
- `429` — rate limited; retry later.

## `POST /v1/push`

Request:

```json
{
  "app": "<app name>",
  "ticket": "<from /v1/register>",
  "type": "alert",
  "blob": "<base64, required when type is \"alert\", at most the app's blob limit>",
  "collapse_id": "<at most 64 bytes, optional>",
  "ttl_seconds": 300
}
```

`type` is `"alert"` (a user-visible notification carrying `blob`) or `"background"` (a silent
wake-up, no `blob`). `ttl_seconds` is `0`-`86400`; `0` asks Apple for best-effort,
immediate-or-never delivery rather than a held, retried one.

On `apns`, an alert reaches the phone as a notification titled and worded by the app's fallback
text, marked `mutable-content`, with `{"v": 1, "b": "<blob>"}` under the app's payload key; a
`background` push is a silent `content-available` one.

On `fcm`, the push is a data-only message (no notification part, so the app always builds the
notification itself from the decrypted blob), restricted to the app's Android package:

| | `alert` | `background` |
|---|---|---|
| data | `{"type": "alert", "v": "1", "b": "<blob>"}` | `{"type": "background", "v": "1"}` |
| FCM priority | `HIGH` | `NORMAL` |
| `ttl` | `ttl_seconds` | `ttl_seconds` |
| `collapse_key` | none | `collapse_id`, when given |

An alert is never collapsed: FCM keeps at most four distinct collapse keys per device, so a key
per alert would let pending alerts fall away.

Response `202`:

```json
{"apns_id": "<the platform's own identifier for the accepted push>"}
```

`apns_id` is Apple's identifier for an `apns` push and FCM's message name for an `fcm` one.

Errors:

- `400` — malformed request: unknown or missing `app`, a missing or invalid field, a wrong type,
  `blob` present for a `background` push or absent for an `alert` one.
- `401` — `{"reason": "InvalidTicket"}` (cannot be opened, was signed by a since-dropped key, or
  belongs to a different app than the request names) or `{"reason": "TicketExpired"}`. Either
  means: stop retrying this push and have the phone register again.
- `410` — `{"reason": "Unregistered" | "BadDeviceToken" | "DeviceTokenNotForTopic"}`. Apple or
  Google has said this device token will never accept another push (for `fcm`: the token is
  unregistered, malformed, or belongs to another app than the Android package). Delete whatever
  local subscription record the ticket belongs to.
- `413` — the request body, or `blob`, exceeded the size limits.
- `429` — `{"retry_after_seconds": <int>}`. The ticket or the caller's IP address hit a rate
  limit; back off for at least that long. Transient: retry later, don't drop anything.
- `502` — Apple's or Google's API itself failed or timed out, or the relay's credential for it was
  refused. Transient: retry with backoff.

## `GET /healthz`

`200` with a plain-text body once the process is up. There is nothing to check besides Apple's and
Google's APIs, which are only called per request.

## `GET /metrics`

Prometheus text format; every series carries the `app` it belongs to, or `none` when the request
never resolved to an app:

- `pushrelay_push_total{app, platform="apns|fcm", type="alert|background", result="success|gone|ratelimited|failure|invalid_ticket|app_mismatch"}`
- `pushrelay_register_total{app, platform="apns|fcm|none", result="success|invalid|ratelimited"}`
- `pushrelay_ratelimited_total{app, scope="ticket_alert|ticket_alert_daily|ticket_background|ip_push|ip_register"}`

## Rate limits

Enforced in memory, per process, reset by a restart — a few minutes of lost limits cost less than
a shared store this service would otherwise need. A caller that hits a limit gets a `429`, never
a dropped request. The numbers are the defaults in `config/config.yaml`; an app may override the
per-ticket ones.

| Scope | Default |
|---|---|
| Alert pushes, per ticket | 60/hour (burst 30), 500/day |
| Background pushes, per ticket | 12/hour |
| Pushes, per source IP (all apps together) | 1200/hour |
| Registrations, per source IP (all apps together) | 30/hour |
| Request body | 8 KB |
| `blob` field | 3072 characters |

The per-IP limits key on `X-Forwarded-For`'s first entry when the header is present, and on the
TCP peer address otherwise. That is only safe behind a proxy that sets or overwrites the header
itself rather than forwarding whatever a caller sent: one that appends to an attacker-supplied
value lets the attacker's own first entry stand in for any IP they like. A reverse proxy may also
apply its own, coarser rate limiting; that is a second, independent layer.

## Tickets

A ticket is `version | key id | nonce | AES-256-GCM(plaintext)`, base64url without padding. Every
version has its own AAD, so a ticket never opens as another version.

- Version 1: `token length | device token | issued-at`. No app id; opens only when a legacy app is
  configured, and belongs to that app.
- Version 2: `app id | token length | device token | issued-at`. An APNs ticket; the app id is
  authenticated.
- Version 3: `app id | platform | token length (2 bytes) | token | issued-at`. Issued for every
  platform but `apns`, whose tickets stay version 2; a version 3 ticket also opens with the
  platform `apns`.

Callers never parse a ticket, so the platform needs no field of their own.
