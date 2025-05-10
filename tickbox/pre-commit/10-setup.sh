#!/usr/bin/env bash
# TODO: Make his a feature of tickbox.
set -ueo pipefail
if [[ "${NODIFF:-}" = "true" ]]; then
        ln -s "$(pwd)" "$TICKBOX_TEMPDIR/work"
        exit 0
fi
mkdir "$TICKBOX_TEMPDIR/work"
git archive HEAD | tar -x -C "$TICKBOX_TEMPDIR/work"
git diff --cached --binary | (
        cd "$TICKBOX_TEMPDIR/work"
        git apply
)
