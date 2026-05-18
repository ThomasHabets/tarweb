#!/usr/bin/env bash
set -euo pipefail
[ -z "$(git status --porcelain)" ] || {
    echo "git client not clean"
    exit 1
}
