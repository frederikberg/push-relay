# Development

Go, standard library plus `apns2`, `golang.org/x/oauth2` (the Firebase service-account sign-in),
Prometheus's client and a YAML parser. No generated code.

## Build and test

```
go build ./...
go vet ./...
gofmt -l .            # prints nothing when formatted
go test ./...
```

The tests need no network and no Apple or Google credentials: pushes go to a fake, notification
payloads are built by pure functions the tests inspect, and the FCM sender is exercised against a
local fake of Google's token and send endpoints.

The chart and the image have their own checks, which CI runs when their files change:

```
helm lint charts/push-relay
helm template ci charts/push-relay -f values.yaml     # any values satisfying the required ones
podman build -t push-relay:local .
CONTAINER_RUNTIME=podman scripts/smoke-image.sh push-relay:local
```

`scripts/smoke-image.sh` starts the image with a generated throwaway key and walks health,
registration for two apps, a refused cross-app push, a refused Android registration and the metrics, without contacting Apple.

## Layout

| File | Owns |
|---|---|
| `main.go` | flags, wiring, shutdown |
| `config.go`, `config/config.yaml` | layered configuration and its validation; the defaults |
| `apps.go` | the app table and its lookups |
| `ticket.go` | ticket sealing and opening, ticket keys |
| `handlers.go` | the HTTP API |
| `apns.go` | building and sending the push, classifying Apple's answers |
| `fcm.go` | the same for FCM: service-account sign-in, data message, Google's answers |
| `ratelimit.go` | in-memory token buckets |
| `metrics.go` | the Prometheus series |

A new configuration value goes into `config/config.yaml` with its default and a comment, into the
raw and validated structs in `config.go`, and nowhere else: there are no defaults in code.

## Releasing

A release is a tag on the merge commit of a pull request that bumped the chart's `version` and
`appVersion` (they are equal, and the image tag is derived from the git tag) and moved
`CHANGELOG.md`'s `[Unreleased]` entries into a dated section. `scripts/check-release-versions.sh`
checks all of that and runs in the pull-request checks without a tag.

```
git tag -a vX.Y.Z -m "Release vX.Y.Z" <merge commit> && git push origin vX.Y.Z
```

The tag runs the release workflow: the guard and the tests, then the multi-arch image and the
chart to GHCR (`ghcr.io/frederikberg/push-relay`, `oci://ghcr.io/frederikberg/charts`), then a
GitHub release whose body is the changelog section. A package GHCR creates for the first time may
start private; set it public once in the package settings.
