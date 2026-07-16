#!/bin/sh
# Start OpenOCD (bit-banged SWD) on the UNO Q and forward the gdb port to localhost:3333.
# ponytail: arduino-debug already wraps the openocd invocation; we just stop the router and run it.
set -e

# The router doesn't hold the SWD lines (25/26/38) — it only grabs line 70 — so leave it running.
# The only real hazard is a stale openocd from a previous run still holding the gpio lines.
adb shell 'sudo pkill -x openocd 2>/dev/null; arduino-debug' &
OCD=$!
trap 'kill $OCD 2>/dev/null; adb shell sudo pkill -x openocd' EXIT INT TERM

until adb forward tcp:3333 tcp:3333 2>/dev/null; do sleep 0.3; done
echo "gdb server on localhost:3333 — target extended-remote localhost:3333"
wait $OCD
