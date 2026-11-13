# Two stages: build a static binary with the Go toolchain, then ship nothing else. There is no
# runtime dependency (no interpreter, no shared libs to pin) — this is a small, always-on service
# that anyone's cluster pulls sight-unseen.
FROM docker.io/library/golang:1.27-bookworm AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./
# CGO_ENABLED=0 is what makes the binary static — cross-building this on an arm64 CI runner for
# an amd64 node (or the reverse) must never silently link against the build host's libc.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/push-relay .

# distroless/static, not scratch: this binary makes outbound TLS calls to Apple's API and needs
# the CA bundle static-debian12 already carries — scratch would need one copied in by hand, one
# more thing to keep in sync with the build image's own certs.
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.source="https://github.com/frederikberg/push-relay" \
      org.opencontainers.image.description="Forwards encrypted push notifications to Apple for any number of apps" \
      org.opencontainers.image.licenses="MIT"

COPY --from=build /out/push-relay /push-relay
COPY config/config.yaml /config/config.yaml

# distroless/static's nonroot image already runs as uid 65532 — the chart's own securityContext
# pins the same value explicitly rather than trusting the image default silently — so no USER
# directive is needed here. A deployment mounts its sparse override at /config-custom/config.yaml
# and the APNs key wherever apns.key_path points.
ENTRYPOINT ["/push-relay", "-config", "/config/config.yaml", "-config-custom", "/config-custom/config.yaml"]
