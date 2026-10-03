#!/bin/sh
set -eu
umask 077
bridge_root="${HERMES_EMAIL_BRIDGE_HOME:-$HOME/Library/Application Support/HermesEmailBridge}"
delivery_config="$bridge_root/config/email-delivery.env"
[ -f "$delivery_config" ] || exit 78
config_mode=$(stat -f '%Lp' "$delivery_config" 2>/dev/null || stat -c '%a' "$delivery_config")
[ "$config_mode" = 600 ] || exit 78
set -a
. "$delivery_config"
set +a
: "${EMAIL_BRIDGE_VENV:?}"
: "${EMAIL_BRIDGE_DB_PATH:?}"
: "${EMAIL_DELIVERY_QUEUE_URL:?}"
: "${NYLAS_GRANT_ID:?}"
: "${AWS_REGION:?}"
exec "$EMAIL_BRIDGE_VENV/bin/python" -m hermes_email_bridge.delivery_worker \
    --db-path "$EMAIL_BRIDGE_DB_PATH" --queue-url "$EMAIL_DELIVERY_QUEUE_URL" \
    --grant-id "$NYLAS_GRANT_ID" --region "$AWS_REGION"
