#!/bin/sh
clamd &
sleep 2
exec /usr/local/bin/app-server "$@"
