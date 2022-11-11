#!/usr/bin/env bash
#
# The world's ugliest load test server. Pair up with bench-client.sh
# and you have the world's ugliest benchmarking setup.
#
# See bench-client.sh for more info
#

set -e

while true; do
    SIZE=$(nc -ulp 12345 -q1 < /dev/null)
    echo "Running with limit ${SIZE?}"
    ./tarweb \
        -f site2.tar \
        -S "${SIZE?}" &
    PID="$!"
    nc -ulp 12346 -q0 < /dev/null
    kill -INT "${PID?}" || true
    wait
done
