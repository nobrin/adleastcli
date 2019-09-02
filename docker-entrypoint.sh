#!/bin/bash
set -e
DAEMON=adleastcli

stop() {
        echo "Received SIGINT or SIGTERM. Shutting down $DAEMON"

        # Get PID
        pid=$(cat /tmp/${DAEMON}.pid)
        # Set TERM
        kill -s INT "${pid}"
}

trap stop SIGINT SIGTERM

adleastcli -S $ADL_DOMAIN httpd &

pid="$!"
echo "${pid}" > /tmp/${DAEMON}.pid
wait "${pid}" && exit $?

