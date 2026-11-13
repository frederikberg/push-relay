#!/usr/bin/env bash
# Verifies that every place a version is written agrees, and with the release tag when one is
# given:
#   scripts/check-release-versions.sh [v0.1.0]
# The places are the chart's `version` and `appVersion` (the image tag is derived from the git
# tag) and the CHANGELOG.md section of that version. Prints every disagreement, not just the
# first, and exits non-zero when there is one.
set -u

root="$(cd "$(dirname "$0")/.." && pwd)"
chart="$root/charts/push-relay/Chart.yaml"
problems=0

field() { sed -n "s/^$1:[[:space:]]*//p" "$chart" | head -n1 | tr -d "\"'"; }
fail() { echo "FAIL: $*" >&2; problems=$((problems + 1)); }

chart_version="$(field version)"
app_version="$(field appVersion)"
echo "Chart.yaml version     $chart_version"
echo "Chart.yaml appVersion  $app_version"

semver='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'
[[ "$chart_version" =~ $semver ]] || fail "chart version '$chart_version' is not a semantic version"
[ "$chart_version" = "$app_version" ] || fail "chart version '$chart_version' and appVersion '$app_version' differ"

if [ -n "${1:-}" ]; then
  tag_version="${1#v}"
  echo "git tag                $tag_version"
  [ "$chart_version" = "$tag_version" ] || fail "tag '$tag_version' does not match chart version '$chart_version'"
fi

if ! "$root/scripts/extract-changelog.sh" "$chart_version" > /dev/null; then
  fail "CHANGELOG.md has no section for $chart_version"
fi

if [ "$problems" -ne 0 ]; then
  echo "$problems problem(s)" >&2
  exit 1
fi
echo "OK"
