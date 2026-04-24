#!/usr/bin/env bash
exit 0
set -ueo pipefail
cd "$TICKBOX_TEMPDIR/work"
export CARGO_TARGET_DIR="$TICKBOX_CWD/target/${TICKBOX_BRANCH}.clippy"
exec cargo +nightly clippy --all-features --all-targets -- -W clippy::pedantic -D warnings
