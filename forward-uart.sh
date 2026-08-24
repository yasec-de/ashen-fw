#!/bin/sh
# Forward the STM32 UART (/dev/ttyHS1 on the UNO Q) over adb to a local TCP
# socket. Stays in the foreground until Ctrl-C, then restores arduino-router.
set -e

BAUD=${BAUD:-4000000}
DEV=${DEV:-/dev/ttyHS1}
PORT=${PORT:-7600}
BOOT_GPIO=${BOOT_GPIO:-70}
GPIOCHIP=${GPIOCHIP:-/dev/gpiochip1}

adb shell "\
	sudo mkdir -p /run/systemd/system/arduino-router.service.d; \
	printf '[Service]\nRestart=no\n' | sudo tee /run/systemd/system/arduino-router.service.d/99-forward.conf >/dev/null; \
	sudo systemctl daemon-reload; \
	sudo systemctl stop arduino-router-serial.path arduino-router-serial.service arduino-router.service; \
	sudo pkill -9 arduino-router 2>/dev/null; \
	sleep 0.5; \
	sudo gpioset -c $GPIOCHIP $BOOT_GPIO=1 & \
	sudo socat TCP-LISTEN:$PORT,reuseaddr,fork FILE:$DEV,raw,b$BAUD,echo=0" &
target_pid=$!

cleanup() {
	kill $target_pid 2>/dev/null
	adb shell "sudo pkill -9 -x socat; \
		sudo pkill -9 -x gpioset; \
		sudo rm -f /run/systemd/system/arduino-router.service.d/99-forward.conf; \
		sudo systemctl daemon-reload" >/dev/null 2>&1
	exit 0
}
trap cleanup INT TERM EXIT

adb forward tcp:$PORT tcp:$PORT >/dev/null
echo "Bound to $PORT — Ctrl-C to stop"
wait $target_pid
