#!/usr/bin/env bash
set -euo pipefail
VERSION="$(awk '/^version/ {print $3}' Cargo.toml | head -1 | sed 's/"//g')"
exec git commit -nam"Bump version to ${VERSION}"
