# hermes-email-bridge

`hermes-email-bridge` routes inbound email into [Hermes Agent](https://github.com/NousResearch/hermes-agent). It normalizes provider payloads, maps email threads to Hermes sessions, invokes Hermes, and can send the response back through the email provider.

AgentMail is the first adapter, not a core dependency. The bridge contract is intentionally small enough for future IMAP, Gmail API, Postmark, SendGrid, or SES adapters.

> Status: alpha. Start with replies disabled and dry-run enabled.

## What works

- AgentMail polling, message inspection, threaded replies, and verified webhooks
- Provider-neutral typed message and attachment models
- Authorization-aware SQLite mappings bound to a provider-authenticated participant
- Hermes session creation and resume through its non-interactive CLI
- JSON structured logs with secret-field redaction
- Persistent poll cursor, processed-message idempotency, and optional raw payload storage
- No runtime Python dependencies

## Install

Python 3.11 or newer is required. The default macOS Python 3.9 is not supported.

### Recommended: uv

```bash
git clone https://github.com/aulbricht/hermes-email-bridge.git
cd hermes-email-bridge
uv sync
cp .env.example .env
```

For development tools and tests, use `uv sync --extra dev`. Run commands with
`uv run`, for example `uv run hermes-email-bridge init-db`.

### pip fallback

Create the virtual environment with Python 3.11 or newer explicitly, then update
pip before requesting an editable Hatchling install:

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
cp .env.example .env
```

Edit `.env`, then export it before invoking the CLI:

```bash
set -a
source .env
set +a
```

The bridge does not parse `.env` itself, avoiding a runtime dependency and keeping secret loading under the process supervisor's control.

## Configure

| Variable | Default | Purpose |
| --- | --- | --- |
| `EMAIL_BRIDGE_PROVIDER` | `agentmail` | Active provider adapter |
| `AGENTMAIL_API_KEY` | required | AgentMail bearer API key |
| `AGENTMAIL_INBOX_ID` | required | Inbox address or ID |
| `AGENTMAIL_WEBHOOK_SECRET` | required by `serve` | Svix signing secret (`whsec_…`) |
| `EMAIL_BRIDGE_DB_PATH` | `~/.local/state/hermes-email-bridge/bridge.db` | SQLite database |
| `EMAIL_BRIDGE_SEND_REPLIES` | `false` | Allow outbound replies |
| `EMAIL_BRIDGE_DRY_RUN` | `true` | Skip provider send even when replies are enabled |
| `AGENTMAIL_BASE_URL` | `https://api.agentmail.to/v0` | HTTPS AgentMail API base URL |
| `AGENTMAIL_ALLOW_INSECURE_LOCAL_HTTP` | `false` | Permit HTTP only to `localhost` or a loopback IP for local tests |
| `EMAIL_BRIDGE_STORE_RAW` | `false` | Persist raw provider payloads for debugging |
| `EMAIL_BRIDGE_RAW_RETENTION_DAYS` | `30` | Logical retention limit for opted-in raw payloads |
| `EMAIL_BRIDGE_ALLOW_SUBJECT_RESUME` | `false` | Enable authenticated exact-participant subject fallback |
| `EMAIL_BRIDGE_POLL_INTERVAL` | `30` | Continuous poll interval in seconds |
| `EMAIL_BRIDGE_LOG_LEVEL` | `INFO` | Python log level |
| `HERMES_COMMAND` | `hermes chat --quiet --source tool` | Shell-free Hermes command prefix |
| `HERMES_PROFILE` | `default` | Profile metadata exported to Hermes |
| `HERMES_TIMEOUT` | `300` | Invocation timeout in seconds |
| `EMAIL_BRIDGE_WEBHOOK_HOST` | `127.0.0.1` | Webhook listen host |
| `EMAIL_BRIDGE_WEBHOOK_PORT` | `8787` | Webhook listen port |
| `EMAIL_BRIDGE_WEBHOOK_QUEUE_SIZE` | `8` | Accepted webhook events waiting for a worker |

For a named Hermes profile, point `HERMES_COMMAND` at that profile's Hermes wrapper. The bridge appends `--resume SESSION` when mapped and always appends `--query PROMPT`; it never invokes a shell.

## Use

Initialize the mapping database:

```bash
hermes-email-bridge init-db
```

Poll once, or continuously:

```bash
hermes-email-bridge poll
hermes-email-bridge poll --continuous --interval 15
```

Inspect how a provider message normalizes (add `--raw` to include the raw payload):

```bash
hermes-email-bridge inspect '<message-id@agentmail.to>'
```

List persistent mappings:

```bash
hermes-email-bridge mappings
```

Markers are masked in this output. Rotate one marker and reveal the replacement once:

```bash
hermes-email-bridge mappings rotate 1 --ttl-days 90
```

Purge retained raw payloads without deleting processed-message idempotency records:

```bash
hermes-email-bridge purge-raw --older-than-days 30
```

Run the webhook receiver:

```bash
hermes-email-bridge serve
curl http://127.0.0.1:8787/healthz
```

Expose `/webhooks` through HTTPS and register it for AgentMail's `message.received` event. `serve` refuses to start without `AGENTMAIL_WEBHOOK_SECRET` and verifies the exact raw body using AgentMail's Svix headers before parsing it. Verified events enter a bounded queue and one worker processes them serially so messages cannot race to create or resume the same Hermes session; saturation returns HTTP 503 so the provider can retry. See AgentMail's [webhook setup](https://docs.agentmail.to/webhooks-overview) and [verification](https://docs.agentmail.to/webhook-verification) guides.

To enable actual replies, change both safety gates deliberately:

```bash
export EMAIL_BRIDGE_SEND_REPLIES=true
export EMAIL_BRIDGE_DRY_RUN=false
```

AgentMail's reply endpoint preserves the original email thread, including `In-Reply-To` and `References` semantics.

## Seed a mapping

Inbound mail with no existing mapping starts a new Hermes session. The runner captures the `session_id:` emitted by Hermes and persists the new thread mapping automatically.

For a message originally sent elsewhere, seed its outbound message ID before replies arrive:

```python
from hermes_email_bridge.store import MappingStore

with MappingStore("bridge.db") as store:
    mapping = store.add_mapping(
        provider="agentmail",
        hermes_session="20260709_120000_abc123",
        hermes_topic="client-onboarding",
        provider_thread_id="thd_123",
        subject="Welcome to Hermes",
        participant_email="person@example.com",
        message_ids=("<outbound-message@agentmail.to>",),
    )
    print(f"X-Hermes-Bridge: v1:{mapping.bridge_marker}")
```

The marker is a random opaque capability that only selects an existing database mapping. It does not encode a session, command, or configuration value. New markers expire after 90 days by default and are valid only for the mapping's authenticated participant.

`X-Hermes-Bridge` is still a bearer capability visible to every email recipient and to mail infrastructure that handles the message. Do not reuse or publish it; rotate it if the recipient set changes or a message containing it is exposed.

## Architecture

```mermaid
flowchart LR
    A["AgentMail poll or signed webhook"] --> B["AgentMail adapter"]
    B --> C["NormalizedEmail"]
    C --> D{"Authenticated exact participant?"}
    D -->|"denied"| J["Record denial; no Hermes or mapping mutation"]
    D -->|"authorized / new"| E["SQLite resolver and Hermes runner"]
    E --> F{"Reply gates"}
    F -->|"disabled / dry-run"| G["Structured skip log"]
    F -->|"enabled"| H["Provider threaded reply"]
    E --> I["Marker, message IDs, thread; optional subject"]
```

The provider boundary is [`EmailProvider`](src/hermes_email_bridge/providers/base.py). An adapter implements `poll`, `get`, and `reply`; webhook parsing is optional. Core orchestration has no AgentMail imports.

Resolution order is:

1. Existing opaque bridge marker from provider metadata or `X-Hermes-Bridge`
2. `In-Reply-To`, then newest-to-oldest `References`
3. Provider thread ID
4. Exact normalized subject and participant, only when `EMAIL_BRIDGE_ALLOW_SUBJECT_RESUME=true`

Every resume path is an authorization decision: the provider must classify the sender as authenticated and the normalized sender address must exactly match the mapping's non-null participant. AgentMail authentication comes only from its signed event type or API `received`/`unauthenticated` classification. Raw `Authentication-Results` headers are untrusted and ignored. Failed, missing, or unknown authentication never invokes Hermes, sends a reply, or changes a mapping.

Every authorized match links the inbound and outbound message IDs to the mapping, improving subsequent reply matching. Provider thread IDs are unique per authenticated participant; conflicting attempts cannot overwrite an existing Hermes session.

## Trust boundary

Email is untrusted user content. The bridge never reads commands, session IDs, routing values, or configuration from the body or subject. The body is passed to Hermes inside an explicit user-content boundary; only configured values, verified provider fields, and existing opaque mapping capabilities control the bridge.

Additional safeguards:

- Webhook HMAC signature and five-minute timestamp verification
- Configurable replies plus independent dry-run gate
- No shell evaluation of `HERMES_COMMAND`
- API keys and webhook secrets never logged
- Processed message IDs plus in-process webhook coalescing prevent duplicate Hermes invocations
- AgentMail bearer credentials are sent only to a validated HTTPS origin; redirects are rejected
- Raw payloads default off and, when enabled, are stored only in SQLite and logically purged after the configured retention period

Raw emails can contain sensitive data. Leave `EMAIL_BRIDGE_STORE_RAW=false` unless debugging requires them. The bridge creates a new state directory with mode `0700` and a new database with mode `0600` on POSIX systems, but existing directories, database copies, SQLite sidecars, and backups remain the operator's responsibility. Logical purge sets expired payloads to `NULL`; use your normal SQLite maintenance if physical page reclamation is required.

## Development

```bash
uv sync --extra dev
uv run pytest
uv run ruff check .
uv run mypy
uv run python -m build
```

Tests cover authentication and spoofing rejection, every mapping path, schema migration, marker rotation and expiry, raw retention, URL and redirect rejection, bounded webhook processing, normalization, dry-run behavior, the subprocess runner, and Svix verification.

## AgentMail notes and current limits

The adapter targets AgentMail's documented `/v0/inboxes/:inbox_id/messages` list/get/reply endpoints. Polling uses an overlapping timestamp cursor plus persistent message-ID deduplication because the list API exposes time and page filters rather than a durable event cursor.

Current deliberate limits:

- Attachment metadata is normalized; attachment content is not downloaded or sent to Hermes.
- WebSockets are not implemented because polling and production webhooks cover the initial use cases.
- One process is configured for one AgentMail inbox.
- Webhook duplicate coalescing is in-process; multi-process deployments need a durable database claim or lease.
- A provider reply failure is recorded and logged but is not automatically retried; use the log context for manual recovery.

See the current AgentMail [message API](https://docs.agentmail.to/messages) and [list endpoint](https://docs.agentmail.to/api-reference/inboxes/messages/list) for upstream behavior.

## License

MIT
