#!/bin/sh
set -eu

umask 077

'/Library/Application Support/HermesEmailAgent/hermes-agent/runtime/verify-hermes-email-agent.py' 1>&2

: "${EMAIL_BRIDGE_ENV_FILE:?EMAIL_BRIDGE_ENV_FILE is required}"
if [ ! -f "$EMAIL_BRIDGE_ENV_FILE" ]; then
    echo "email bridge environment file does not exist" >&2
    exit 78
fi
env_mode=$(stat -f '%Lp' "$EMAIL_BRIDGE_ENV_FILE" 2>/dev/null || stat -c '%a' "$EMAIL_BRIDGE_ENV_FILE")
if [ "$env_mode" != "600" ]; then
    echo "email bridge environment file must have mode 0600" >&2
    exit 78
fi

set -a
. "$EMAIL_BRIDGE_ENV_FILE"
set +a

: "${EMAIL_BRIDGE_VENV:?EMAIL_BRIDGE_VENV is required}"
exec "$EMAIL_BRIDGE_VENV/bin/hermes-email-bridge" poll --continuous 1>&2
