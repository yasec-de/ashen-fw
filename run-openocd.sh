#!/bin/sh
# Start OpenOCD (bit-banged SWD) on the UNO Q and forward the gdb port to localhost:3333.
set -e

adb shell 'sudo pkill -x openocd 2>/dev/null; arduino-debug' &
OCD=$!
trap 'kill $OCD 2>/dev/null; adb shell sudo pkill -x openocd' EXIT INT TERM

until adb forward tcp:3333 tcp:3333 2>/dev/null; do sleep 0.3; done
echo "gdb server on localhost:3333 — target extended-remote localhost:3333"
wait $OCD
