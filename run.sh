#!/bin/sh
# Launch APEX JediSyslogger.
#
# Same shape as every other application in the ApexBuild suite: this script
# starts the app through its uniform launcher, and every flag goes straight
# through to it.
#
#   ./run.sh                    on 127.0.0.1:8099
#   ./run.sh --port 8100
#
# Note that this path serves plain http on loopback, which is what the suite
# frames. To run the app the way it ships standalone -- https from
# certs/server.crt -- start it directly:  PORT=8099 node server.js
cd "$(dirname "$0")" || exit 1
exec python3 apexmod run --port 8099 "$@"
