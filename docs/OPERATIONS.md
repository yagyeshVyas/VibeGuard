# Operations Runbook — Approval Service

The approval service is the long-running production component added in v1.14:
password-authenticated human decisions, quorum, signed approval tokens, signed
audit and durable state. This runbook covers deployment, monitoring, backup,
restore and recovery.

## 1. Topology

```
TLS reverse proxy / ingress
        │  127.0.0.1:8787 (or pod:8787)
        ▼
vibeguard approval serve
        ├─ /var/lib/vibeguard/approvals.json
        ├─ /var/lib/vibeguard/approval-audit.jsonl (+ checkpoint, key)
        └─ /etc/vibeguard/{users,signing-keys,*-private.pem}
```

The service is loopback-only by default. Containers set
`VIBEGUARD_APPROVAL_ALLOW_REMOTE=1` and bind inside the container network; the
host/pod port must only be reachable through the TLS proxy or monitoring
namespace. Do not publish the raw HTTP port to the internet.

The JSON store is **single-writer**. Run exactly one replica (`Recreate` on
Kubernetes). Active-active requires a transactional shared store, which is not
implemented.

## 2. Configuration

| Environment | Meaning |
|---|---|
| `VIBEGUARD_APPROVAL_TENANT` / `_ISSUER` | approval tenant and issuer |
| `VIBEGUARD_APPROVAL_HOST` / `_PORT` | bind address/port |
| `VIBEGUARD_APPROVAL_ALLOW_REMOTE` | `1` required for non-loopback bind |
| `VIBEGUARD_APPROVAL_STORE` | ticket/quorum JSON store |
| `VIBEGUARD_APPROVAL_AUDIT` | signed audit JSONL |
| `VIBEGUARD_APPROVAL_AUDIT_KEY` | optional audit private key (default sibling `.key.pem`) |
| `VIBEGUARD_APPROVAL_USERS` | scrypt user file |
| `VIBEGUARD_APPROVAL_SIGNING_KEYS` | human principal → private key path map |
| `VIBEGUARD_APPROVAL_KEY` | approval-token signing key |
| `VIBEGUARD_APPROVAL_IDENTITY_KEY` | VGAT issuing key |
| `VIBEGUARD_APPROVAL_ADMIN` | comma-separated principals allowed to rotate keys |
| `VIBEGUARD_APPROVAL_REQUIRED_APPROVALS` | default quorum 1–5 |
| `VIBEGUARD_APPROVAL_SESSION_TTL` | human session seconds |
| `VIBEGUARD_APPROVAL_SECURE_COOKIES` | `1` when the UI is served over HTTPS |
| `VIBEGUARD_APPROVAL_METRICS_TOKEN` | optional bearer token for `/metrics` |
| `VIBEGUARD_APPROVAL_SHUTDOWN_TIMEOUT` | graceful shutdown milliseconds |

Secrets are files, mode `0600`, owned by the service user. The audit signing key
is generated beside the audit file on first start; back it up with the audit log
or the chain cannot be verified.

## 3. Monitoring

### Endpoints

| Endpoint | Semantics | Probe |
|---|---|---|
| `/health` | process is alive | liveness |
| `/ready` | accepting requests and state dir writable | readiness |
| `/metrics` | Prometheus text | scrape |

Key metrics:

- `vibeguard_approval_ready` — 0 while starting/shutting down.
- `vibeguard_approval_pending_tickets` — backlog.
- `vibeguard_approval_active_sessions` — human UI sessions.
- `vibeguard_approval_requests_total` — tickets requested.
- `vibeguard_approval_decisions_total{decision}` — approved/pending/denied.
- `vibeguard_approval_logins_total{result}` — success/failure.
- `vibeguard_approval_audit_events_total{type}` — audit writes.
- `vibeguard_http_requests_total` / `vibeguard_http_request_duration_seconds_*`.
- `vibeguard_process_resident_memory_bytes`, heap, uptime.

Suggested alerts:

| Alert | Condition |
|---|---|
| Approval service down | `up == 0` for 2m |
| Not ready | `vibeguard_approval_ready == 0` for 5m |
| Audit not advancing | `rate(vibeguard_approval_audit_events_total[10m]) == 0` while requests > 0 |
| Login attack | `rate(vibeguard_approval_logins_total{result="failure"}[5m]) > 0.2` |
| Ticket backlog | `vibeguard_approval_pending_tickets > 50` for 15m |
| Memory pressure | RSS > 400 MiB for 10m |
| Disk pressure | state volume > 85% used |
| Gateway approval rejects | 401/403 spike on `/mcp` (gateway metrics/logs) |

### Logs

The service writes one JSON object per request to stdout: timestamp, level,
event, `request_id`, method, normalized route, status, duration and source IP.
It never logs bodies, passwords, proof tokens or approval tokens. Ship stdout to
your log pipeline; alert on `level=error` and repeated 5xx.

## 4. Backup

Stop writes by draining the instance (readiness false) or briefly stopping the
service. Then:

```bash
vibeguard approval backup \
  --store /var/lib/vibeguard/approvals.json \
  --audit /var/lib/vibeguard/approval-audit.jsonl \
  --out /backup/vibeguard-$(date -u +%Y%m%dT%H%M%SZ) \
  --label nightly
```

The backup includes the store, audit log, checkpoint and audit key. Pass `--used <gateway-used-token-file>` to include the gateway's durable replay store; losing that file resets single-use replay protection. Supply `--key`, `--identity-key`, `--signing-keys` and `--users` (or the matching
environment variables) to include the service/approver configuration files;
restore them to `/etc/vibeguard` separately from the state directory. `manifest.json` records SHA-256 and size
for every file and verifies the signed audit chain before the backup is
accepted. Backups contain approval tokens and key material: encrypt at rest and
restrict access.

Verify:

```bash
vibeguard approval verify-backup --from /backup/vibeguard-...
```

## 5. Restore and recovery

### Corrupt/missing store or audit

1. Stop the service (`systemctl stop` / scale to 0 / `docker compose stop`).
2. Verify the chosen backup (never restore an unverified backup).
3. Restore into the state directory with `--force` only when replacing the
   broken generation:

```bash
vibeguard approval restore --from /backup/vibeguard-... \
  --to /var/lib/vibeguard --force
```

4. Start the service. `/ready` must be 200 and a fresh audit event must appear.
5. Verify the audit chain with `vibeguard audit verify` and the audit public
   key printed at startup.

The restore is verify-then-atomic-copy; a failed hash or audit check aborts
before overwriting anything. A backup containing a duplicate target is rejected.

### Lost audit key

If the audit key is lost, the existing chain is unverifiable and the service
will not start (`existing audit log failed verification`). Restore the key from
backup. If no backup exists, archive the old log for forensics, rotate to a new
empty audit file, and record the gap in the incident ticket. Do not silently
truncate the chain.

### Disk full / permissions

`/ready` returns `state_not_writable`; the service fails closed. Free space or
fix ownership/mode on `/var/lib/vibeguard`, then restart. Never point the state
volume at an ephemeral container layer.

### Crash / restart

Use `Restart=on-failure` (systemd) or `restart: unless-stopped` (Compose) /
Kubernetes restart policy. On startup the service verifies the audit chain and
loads the store atomically. A corrupt store fails startup by design; restore.

### Rollback

Keep the previous image and state backup. With the single-writer store:
1. stop the new instance;
2. restore the pre-upgrade backup if the schema changed;
3. start the previous image;
4. verify `/ready`, `/metrics` and a test ticket/decision.

## 6. Key rotation

- Rotate a human approver key with `POST /approval/keys` using an admin token
  carrying `approval.admin`.
- Rotate the approval-token key by starting with a new `VIBEGUARD_APPROVAL_KEY`
  during a maintenance window; old tokens expire naturally. Gateway verifiers
  must be updated with the new public key.
- Rotate the identity/VGAT key via `vibeguard approval issue` with the new key;
  old short-lived tokens expire within 15 minutes.
- Rotate the audit key only by starting a new audit generation; archive and
  verify the old chain first.

## 7. Graceful shutdown

SIGTERM/SIGINT sets readiness false, emits `service.stop`, stops accepting
connections, drains idle connections and closes after the configured timeout.
Systemd `TimeoutStopSec`/Compose `stop_grace_period` must exceed
`VIBEGUARD_APPROVAL_SHUTDOWN_TIMEOUT`.

## 8. Security checklist

- TLS terminated by a trusted reverse proxy; no raw HTTP exposure.
- Service runs as a dedicated non-root user with a read-only config mount.
- State volume mode `0700`, backups encrypted.
- Private keys never mounted into agent workloads.
- `VIBEGUARD_APPROVAL_METRICS_TOKEN` set if the metrics port is shared.
- Login throttling, CSRF, HttpOnly SameSite cookies and `Secure` cookies enabled
  over HTTPS.
- Audit sink and state directory monitored; fail-closed on audit/state failure.
- One writer; no shared JSON store across replicas.
