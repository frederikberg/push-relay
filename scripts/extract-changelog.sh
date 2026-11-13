#!/usr/bin/env bash
# Prints the body of one version's CHANGELOG.md section, for use as a release body.
#   scripts/extract-changelog.sh 0.1.0      (a leading v is accepted)
# Exits non-zero when the version has no section or the section is empty, so a release cannot
# quietly publish without notes.
set -u

version="${1:-}"
version="${version#v}"
if [ -z "$version" ]; then
  echo "usage: $0 <version>" >&2
  exit 2
fi

changelog="$(dirname "$0")/../CHANGELOG.md"
body="$(awk -v v="$version" '
  /^## / {
    if (found) exit
    heading = $0
    sub(/^## \[?/, "", heading)
    sub(/[] ].*$/, "", heading)
    if (heading == v) { found = 1; next }
  }
  found { print }
' "$changelog")"

# Trim surrounding blank lines.
body="$(printf '%s\n' "$body" | sed -e '/./,$!d' | sed -e ':a' -e '/^\n*$/{$d;N;ba' -e '}')"

if [ -z "$body" ]; then
  echo "CHANGELOG.md has no non-empty section for version $version." >&2
  exit 1
fi
printf '%s\n' "$body"
