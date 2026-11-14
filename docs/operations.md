# Operations

How to run a relay: the Helm chart, the configuration, adding an app, rotating keys, and what the
operator is able to see.

## What a relay needs

- **An Apple Developer team key** (`.p8`): App Store Connect → Users and Access → Integrations →
  Keys. The key id and team id go into the configuration; the `.p8` file stays in a Kubernetes
  Secret. One team key signs for every app of that team, so all apps of one relay belong to one
  team. Apps of another team need their own relay.
- **Optionally, a Firebase service-account key** for Android: a Firebase project with the Android
  apps added, and a service account allowed to send messages (Firebase console → Project settings
  → Service accounts → Generate new private key). The JSON file stays in a Kubernetes Secret.
  One project serves every app of the relay. Without it the relay delivers to iPhones only.
- **Ticket signing keys** in a Secret: `<id>:<64 hex>,<id>:<64 hex>,...` with `openssl rand -hex 32`
  for each key. The first entry seals new tickets, every entry opens.
- **A hostname** with DNS pointing at the cluster's ingress. Let it resolve before installing if
  cert-manager uses an HTTP-01 challenge: a certificate request against a name that does not
  resolve fails, and caching can make the failure outlast the propagation delay.

## Installing

```
helm install push-relay oci://ghcr.io/frederikberg/charts/push-relay \
  --version <version> --namespace push-relay --create-namespace -f values.yaml
```

```yaml
apnsKey:
  existingSecret: push-relay-apns-key        # key AuthKey.p8
fcmKey:                                      # optional, switches on Android
  existingSecret: push-relay-fcm-key         # key service-account.json
ticketKeys:
  existingSecret: push-relay-ticket-keys     # key ticket-keys
config:
  apns:
    key_id: ABC123DEFG
    team_id: HIJ456KLMN
  apps:
    example:
      id: 1
      topic: com.example.app
      payload_key: ex
      fallback_title: Example
      fallback_body: New notification
      android_package: com.example.app       # optional, needed for Android devices
ingress:
  className: nginx
  hosts: [push.example.com]
  tls:
    secretName: push-relay-tls
    certManager:
      enabled: true
      issuerName: letsencrypt
```

The chart never creates the Secrets: an Apple or Google credential and the keys behind every
ticket have no business passing through Helm values. It refuses to render without the APNs key
and ticket keys, without the APNs ids, without an app and without a host; the Firebase key is the
one optional Secret. `values.yaml` documents every chart value.

The container image is public; the chart needs no pull secret. The image is started as
`push-relay -config /config/config.yaml -config-custom /config-custom/config.yaml`: the first file
is baked into the image, the second is the chart's `config` value (any other deployment mounts
its own).

## Configuration

`config/config.yaml` is the only place defaults live, with a comment per option. Layers, later
wins: that file, the sparse override file, then `PUSH_RELAY_<SECTION>_<KEY>` environment
variables for any scalar outside `apps`. `${NAME}` in a string is replaced by the environment
variable `NAME`; the ticket keys reach the service that way. A missing required value, a
misspelled key or an out-of-range number stops the process at start and names the offender.

Only secrets are not in the configuration: the `.p8` file (path `apns.key_path`), the Firebase
service-account file (path `fcm.key_path`) and `TICKET_KEYS`.

## Apps

An app entry is its name, `id`, `topic`, `payload_key`, `fallback_title` and `fallback_body`, plus
optional `android_package` and `limits` overriding the per-ticket defaults.

- **Adding an app** is adding an entry and restarting. The app's iOS build registers with
  `app: <name>`, and its notification extension reads the blob from `payload_key`.
- **The `id` is sealed into every ticket.** Never reuse one for a different app and never change
  an app's: its tickets stop opening (the phones register again) or, worse, open for another app.
  The name can change freely; only the id binds tickets.
- **Android** is available for an app when the relay has an `fcm.key_path` and the app has an
  `android_package` (its Android application id). Registration for the `fcm` platform is refused
  otherwise, and FCM itself rejects a token that belongs to another package. The Android build
  registers with `platform: fcm` and the token its Firebase SDK provides; its messaging service
  receives data messages carrying `type`, `v` and, for an alert, `b` (the blob). The Firebase
  project must be the one the Android build's `google-services.json` came from.
- **Removing an app** invalidates its tickets and its pushes answer `400 unknown app`.

## Legacy tickets

Before tickets named an app, one relay served one app, and its tickets and requests carried no
app. `tickets.legacy_app: <name>` makes the relay accept those: a version 1 ticket belongs to
that app, and a register or push request without `app` means it. Leave it empty on a relay that
never served such tickets. Once every phone has registered again (the ticket lifetime is
`tickets.ttl_days`), remove the setting.

## Rotating the ticket keys

Put a new `<id>:<hex>` entry first, keep the old entries behind it, restart. New tickets are
sealed with the new key and old ones keep opening. To retire a key, drop its entry after its
tickets have expired or after accepting that their phones register again.

## What the operator sees

- **Transiently, per request:** the caller's source IP, the device token (in memory for the one
  request that needs it), the `ticket_id`, the app, the push type, and the blob's size and
  timing.
- **Never:** a notification's content, a badge count, an account, or which server a device
  belongs to beyond IP correlation across requests.
- **Logs and metrics:** `ticket_id`, app and outcome. Never a device token, a ticket or a blob.

A ticket authorizes pushing, within the limits, to one device of one app, and expires on its own.
Holding one never reveals the device token it was issued for, and opening the blob it delivers
needs a content key the relay never has.
