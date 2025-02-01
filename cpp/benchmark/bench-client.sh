#!/usr/bin/env bash
#
# The world's ugliest load test client. Pair up with bench-server.sh
# and you have the world's ugliest benchmarking setup.
#
# I can do much better, but this took like 5min to write. It produces
# data I believe. So if it works then it ain't stupid?
#
# With default parameters below it takes about 10h.
#
# It sends a UDP packet to start the server, and then again to stop
# it.
#

set -e

HOST=$1
for kb in $(seq 1 20 10000); do
    #echo "2000000000" | nc -u -q0 ${HOST?} 12345
    echo "1"         | nc -u -q0 ${HOST?} 12345
    sleep 2
    for n in $(seq 1000); do
        curl -o /dev/null \
             -k \
             -4 \
             -r "0-$(expr ${kb?} "*" 1000)" \
             http://${HOST?}:8787/1GB.bin
    done
    for n in $(seq 10); do 
        echo "1" | nc -u -q0 ${HOST?} 12346
    done
    sleep 2
done
