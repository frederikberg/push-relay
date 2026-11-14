# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-11-14

### Added

- Delivery to Android through Firebase Cloud Messaging, beside APNs. `POST /v1/register` takes a
  `platform` (`apns` or `fcm`) and a `token`; `apns_token` keeps working for `apns`. Alerts go out
  as high-priority FCM data messages restricted to the app's Android package, silent syncs as
  normal-priority ones.
- Ticket version 3 carries the platform. iPhone tickets keep the version 2 format, and every
  earlier ticket keeps opening.
- Options: `fcm.key_path` (the Firebase service-account key; empty leaves Android off),
  `fcm.api_base`, `fcm.send_timeout_seconds`, and `android_package` per app. The chart takes an
  optional `fcmKey.existingSecret`.
- Metrics are served on their own listener (`server.metrics_addr`), never on the public one; the
  chart's Service and ServiceMonitor use it.
- Rate-limit state is bounded (`max_tracked_keys` per scope, least recently used forgotten first)
  and IPv6 sources count as their /64.
- Metrics carry a `platform` label on `pushrelay_push_total` and `pushrelay_register_total`.

### Changed

- A failed push logs a short reason next to the result.

## [0.1.0] - 2026-11-13

### Added

- First release: a stateless relay that forwards encrypted push notifications to Apple for any
  number of apps, with sealed expiring tickets, per-app topic, banner text, payload key and
  limits, a single APNs key, Prometheus metrics, a container image and a Helm chart.
- Ticket version 2 names the app it was issued for; a ticket can only push for that app.
- Tickets of the previous format, issued by the relay this project grew out of, keep opening for
  the app named by `tickets.legacy_app`, and requests without an `app` field resolve to it, so
  existing installations keep working until they register again.
