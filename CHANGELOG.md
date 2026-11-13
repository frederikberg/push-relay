# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-13

### Added

- First release: a stateless relay that forwards encrypted push notifications to Apple for any
  number of apps, with sealed expiring tickets, per-app topic, banner text, payload key and
  limits, a single APNs key, Prometheus metrics, a container image and a Helm chart.
- Ticket version 2 names the app it was issued for; a ticket can only push for that app.
- Tickets of the previous format, issued by the relay this project grew out of, keep opening for
  the app named by `tickets.legacy_app`, and requests without an `app` field resolve to it, so
  existing installations keep working until they register again.
