#!/usr/bin/env bash
set -euo pipefail
CURRENT="$(awk '/^version/ {print $3}' Cargo.toml | head -1 | sed 's/"//g')"
AUTO_NEW_VERSION="$(echo $CURRENT | awk -F. '{print $1 "." $2 "." $3+1}')"
NEW="${BUMP_NEW_VERSION:-$AUTO_NEW_VERSION}"

# MANUAL_VERSION is set manually by the person running the release.
NEW="${MANUAL_VERSION:-$NEW}"
echo "Current: '$CURRENT', New: '$NEW'"
sed -i "s/^version = \"${CURRENT?}\"/version = \"${NEW?}\"/" \
        Cargo.toml \
