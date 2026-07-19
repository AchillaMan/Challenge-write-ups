#!/bin/sh
set -eu

mkdir -p /run/ivi /var/lib/ivi/assets /etc/ivi

rm -f /run/ivi/bus.sock
/usr/bin/dbus-daemon --session --nofork --nopidfile --address=unix:path=/run/ivi/bus.sock &
DBUS_PID=$!

for _ in $(seq 1 50); do
    if [ -S /run/ivi/bus.sock ]; then
        break
    fi
    sleep 0.1
done

/usr/bin/socat TCP-LISTEN:4000,reuseaddr,fork EXEC:/usr/local/bin/ivi_server &
SOCAT_PID=$!

trap 'kill "$SOCAT_PID" "$DBUS_PID" 2>/dev/null || true' INT TERM EXIT

while :; do
    if ! kill -0 "$DBUS_PID" 2>/dev/null; then
        break
    fi
    if ! kill -0 "$SOCAT_PID" 2>/dev/null; then
        break
    fi
    sleep 1
done

kill "$SOCAT_PID" "$DBUS_PID" 2>/dev/null || true
wait "$SOCAT_PID" 2>/dev/null || true
wait "$DBUS_PID" 2>/dev/null || true
