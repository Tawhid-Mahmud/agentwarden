# SIEM export and OpenTelemetry

AgentWarden's audit log is the record of what every agent was allowed to do. This page covers
getting that record into a SIEM, and getting operational telemetry into your tracing and metrics
stack.

- **Audit export** (`agentwarden audit export`, `GET /v1/audit/export`) streams every audit entry as
  [OCSF](https://ocsf.io) 1.3 events, or as AgentWarden's native JSON. The exporter checks the hash
  chain as it goes.
- **OpenTelemetry** (`AGENTWARDEN_OTEL=true`) emits a trace per decision and counters and
  histograms for decisions and tokens.

## Audit export

### Push: the exporter

```bash
# Everything so far, as OCSF JSON lines, to a file your log shipper tails
agentwarden audit export --sink /var/log/agentwarden/ocsf.jsonl

# Keep going: poll every 5 seconds and POST new entries to an HTTPS collector
AGENTWARDEN_EXPORT_TOKEN=... agentwarden audit export --follow \
  --sink https://collector.example.com/agentwarden --cursor collector
```

| Option | Meaning |
|---|---|
| `--sink` | `-` (stdout), a file path (appended to, fsynced before the cursor moves), or an `https://` URL (`http://` only for loopback) |
| `--format` | `ocsf` (default) or `native` (the audit entry as stored, with `seq`, `hash`, `prev_hash`) |
| `--cursor` | Name of the cursor, one per destination; it lives in the database, so any instance can resume it |
| `--follow`, `--interval` | Keep exporting new entries; sink errors are retried without losing data |
| `--reset start\|head` | Re-export everything, or skip to entries written from now on |
| `AGENTWARDEN_EXPORT_TOKEN` | Sent as `Authorization: Bearer ...` to webhook sinks |

Webhook sinks POST each batch (up to `--batch`, default 500) as one JSON array. That suits generic
HTTP inputs such as Cribl, Vector, Fluent Bit, Logstash's `http` input, or Splunk HEC's raw
endpoint (`/services/collector/raw`). For collectors that want their own envelope (Elasticsearch
`_bulk`, Splunk's `/services/collector/event`), write to a file and let Elastic Agent, Filebeat or
the Splunk Universal Forwarder ship it. From Python, `WebhookSink(url, headers={...})` sets
arbitrary headers.

**Delivery is at-least-once.** The cursor only moves after the sink accepts a batch. If a crash
lands between the two, the batch is sent again. De-duplicate on `metadata.uid` (OCSF) or `hash`
(native), which is the entry's chain hash and unique per entry.

**Export checks the chain.** The cursor stores the hash of the last entry it delivered. Before each
batch, the exporter checks that this entry is unchanged, then that every new entry links to the
previous one and matches its own hash. If anyone with database access edits, deletes or re-links
history that was already exported (including truncating the tail and appending a forged,
internally consistent replacement), export stops with `TAMPERED: audit chain broken at seq N`
(exit code 1) and sends nothing after the last good entry. Alert on that.

### Pull: the API

SIEMs that poll can page through the chain themselves:

```bash
curl -s "localhost:8000/v1/audit/export?after_seq=0&limit=500" -H "X-Admin-Key: $ADMIN_KEY"
```

```json
{
  "format": "ocsf",
  "events": [ ... ],
  "next": { "after_seq": 500, "after_hash": "9f2c..." }
}
```

Send `next` back as query parameters for the following page. If the entries you already hold were
changed since, the response is `409` with the `seq` where the chain breaks. `format=native` returns
stored entries.

### OCSF mapping

| AgentWarden event | OCSF class | Activity | Status |
|---|---|---|---|
| `token.issued`, `token.exchanged` | Authentication (3002) | Authentication Ticket (3) | Success |
| `token.denied` | Authentication (3002) | Authentication Ticket (3) | Failure |
| `token.delegated` / `token.delegation_denied` | Authentication (3002) | Service Ticket Request (4) | Success / Failure |
| `token.revoked`, `subject.revoked` | Authentication (3002) | Logoff (2) | Success |
| `auth.failed` | Authentication (3002) | Logon (1) | Failure |
| `authz.decision` | API Activity (6003) | Other (99) | allow → Success, deny → Failure, require_approval → Other |
| `agent.registered` | Account Change (3001) | Create (1) | Success |
| `agent.enabled` / `agent.disabled` | Account Change (3001) | Enable (2) / Disable (5) | Success |
| `agent.scopes_changed` | Account Change (3001) | Other (99) | Success |
| `approval.requested` / `approved` / `denied` | Entity Management (3004) | Create (1) / Update (3) | Success |
| `approval.misuse` | Entity Management (3004) | Other (99) | Failure |
| `keys.rotated` / `keys.pruned` | Entity Management (3004) | Create (1) / Delete (4) | Success |
| anything else | Base Event (0) | Other (99) | Other |

The fields that make these events useful:

- `actor.user.uid`: the human the agent acts for (or the admin/reviewer for admin actions).
  `actor.app_name`: the acting agent. `actor.app_uid`: the full delegation chain
  (`inbox-assistant/summarizer`).
- `api.operation`: the tool. `metadata.correlation_uid`: the decision ID, which the agent and tool
  also see. `metadata.trace_uid`: the OpenTelemetry trace of the decision (when tracing is on).
- `severity_id`: authorization decisions take it from the risk level (none → Informational …
  critical → Critical), and denials are at least Medium. Failed sign-ins, denied tokens and kill
  switches are Medium, and approval misuse is High.
- `metadata.event_code`: the AgentWarden event name. `metadata.uid`: the chain hash.
  `metadata.sequence`: the chain position.
- `unmapped.agentwarden`: the complete original entry (risk signals, matched policy rules,
  redacted argument preview, argument hash, context sources), so a detection rule can use anything
  AgentWarden recorded.

Secrets are redacted before entries are written, so exports never contain them. The mapping fills
the OCSF fields AgentWarden has data for. It has not been run through the OCSF schema validator,
and some classes' recommended fields (for example `src_endpoint`) are absent because AgentWarden
doesn't record them.

### Detection ideas

- `class_uid = 6003 AND status_id = 2 AND severity_id >= 4`: high-risk denied tool calls (likely
  injection attempts). Group by `actor.app_name`.
- `metadata.event_code = "approval.misuse"`: approvals replayed or used for a different call.
- `class_uid = 3002 AND status_id = 2`, many per `actor.user.uid`: credential stuffing or token
  replay.
- `class_uid = 3001 AND activity_id = 5`: someone pulled an agent's kill switch.
- The exporter exiting with `TAMPERED`: the audit database was modified.

## OpenTelemetry

`pip install 'agentwarden[otel]'` (included in the Docker image), then:

```bash
export AGENTWARDEN_OTEL=true
export OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318   # standard OTLP/HTTP variables
agentwarden serve
```

Embedded in your own process, `Gateway.build(telemetry=Telemetry(tracer_provider, meter_provider))`
uses your providers. Without arguments it uses the global ones, which works with
`opentelemetry-instrument`. Without the OpenTelemetry API installed, telemetry is a no-op.

**Spans**

| Span | Attributes |
|---|---|
| `agentwarden.authorize` | `agentwarden.tool`, `.agent_id`, `.decision`, `.decision_id`, `.risk.score`, `.risk.level`, `.risk.signals`, `.policy.rules`, `.approval_pending`; error status and `error.type` on failures |
| ↳ `agentwarden.risk`, `agentwarden.policy` | timing of each stage |
| `agentwarden.token.issue`, `.token.exchange` | `agentwarden.agent_id`, `.dpop`, `.scopes` |
| `agentwarden.token.delegate` | `agentwarden.sub_agent_id`, `.delegation_depth` |

Each `authz.decision` audit entry records the `trace_id` of its span, and each span carries the
`decision_id` of its audit entry, so you can go from one to the other in either direction.

**Metrics**

| Metric | Type | Attributes |
|---|---|---|
| `agentwarden.decisions` | counter | `agentwarden.decision`, `.tool`, `.agent_id` |
| `agentwarden.authorize.duration` | histogram (s) | `agentwarden.decision`, `.tool` |
| `agentwarden.tokens` | counter | `agentwarden.operation` (issue/delegate), `.outcome` (issued/denied), `.agent_id` |

**What telemetry never contains:** user IDs, tool arguments, prompts, context or tokens. Traces
usually leave the security boundary the audit log stays inside, and are sampled. They are for
operations. The audit log (and its SIEM export) remains the security record.
