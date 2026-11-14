#!/usr/bin/env bash
# Starts a built image with a throwaway APNs key and a minimal override, and walks the paths
# that need no Apple connection: health, registration for two apps, a refused cross-app push, a
# refused Android registration and the metrics.
#   scripts/smoke-image.sh <image>        (CONTAINER_RUNTIME=podman to use podman)
set -u

image="${1:?usage: $0 <image>}"
runtime="${CONTAINER_RUNTIME:-docker}"
work="$(mktemp -d)"
name="push-relay-smoke-$$"
port="${SMOKE_PORT:-18080}"
metrics_port="${SMOKE_METRICS_PORT:-19090}"

# shellcheck disable=SC2329  # invoked through the EXIT trap
cleanup() {
  "$runtime" rm -f "$name" > /dev/null 2>&1
  rm -rf "$work"
}
trap cleanup EXIT

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$work/AuthKey.p8" 2> /dev/null || exit 1
cat > "$work/config.yaml" <<'YAML'
apns:
  key_id: SMOKE00000
  team_id: SMOKE00000
tickets:
  legacy_app: alpha
apps:
  alpha:
    id: 1
    topic: com.example.alpha
    payload_key: al
    fallback_title: Alpha
    fallback_body: New alpha
    android_package: com.example.alpha
  beta:
    id: 2
    topic: com.example.beta
    payload_key: be
    fallback_title: Beta
    fallback_body: New beta
YAML
chmod 644 "$work/AuthKey.p8" "$work/config.yaml"

"$runtime" run -d --name "$name" -p "127.0.0.1:$port:8080" -p "127.0.0.1:$metrics_port:9090" \
  -e TICKET_KEYS="1:$(openssl rand -hex 32)" \
  -v "$work/config.yaml:/config-custom/config.yaml:ro" \
  -v "$work/AuthKey.p8:/secrets/apns/AuthKey.p8:ro" \
  "$image" > /dev/null || exit 1

base="http://127.0.0.1:$port"
for _ in $(seq 1 30); do
  curl -fsS "$base/healthz" > /dev/null 2>&1 && break
  sleep 1
done
curl -fsS "$base/healthz" > /dev/null || { "$runtime" logs "$name"; echo "FAIL: not healthy" >&2; exit 1; }

token="$(printf 'ab%.0s' $(seq 1 32))"
register() {
  curl -fsS -X POST "$base/v1/register" -H 'Content-Type: application/json' \
    -d "{\"app\":\"$1\",\"apns_token\":\"$token\"}"
}
ticket_of() { sed -n 's/.*"ticket":"\([^"]*\)".*/\1/p'; }

alpha_ticket="$(register alpha | ticket_of)"
beta_ticket="$(register beta | ticket_of)"
if [ -z "$alpha_ticket" ] || [ -z "$beta_ticket" ]; then
  echo "FAIL: registration returned no ticket" >&2
  exit 1
fi

# A beta ticket named for alpha is refused before anything is sent to Apple.
code="$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$base/v1/push" -H 'Content-Type: application/json' \
  -d "{\"app\":\"alpha\",\"ticket\":\"$beta_ticket\",\"type\":\"background\",\"ttl_seconds\":0}")"
[ "$code" = "401" ] || { echo "FAIL: cross-app push answered $code, want 401" >&2; exit 1; }

# Without a Firebase key the relay delivers to iPhones only and refuses to issue Android tickets.
code="$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$base/v1/register" -H 'Content-Type: application/json' \
  -d '{"app":"alpha","platform":"fcm","token":"abcdefghijklmnopqrstuvwxyz:0123456789"}')"
[ "$code" = "400" ] || { echo "FAIL: fcm registration without a key answered $code, want 400" >&2; exit 1; }

# Metrics live on their own listener, never on the public one.
code="$(curl -sS -o /dev/null -w '%{http_code}' "$base/metrics")"
[ "$code" = "404" ] || { echo "FAIL: /metrics on the public listener answered $code, want 404" >&2; exit 1; }
curl -fsS "http://127.0.0.1:$metrics_port/metrics" | grep -q 'pushrelay_register_total{app="beta",platform="apns",result="success"} 1' \
  || { echo "FAIL: metrics miss the beta registration" >&2; exit 1; }

echo "OK"
