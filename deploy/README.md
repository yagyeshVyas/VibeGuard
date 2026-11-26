# Deployment

Production-shaped deployment for the VibeGuard approval service. The service is
loopback-first; containers bind `0.0.0.0` only inside an isolated network and
must sit behind a TLS reverse proxy.

## Components

| File | Purpose |
|---|---|
| `Dockerfile` | multi-stage Node 22 image, non-root `node`, read-only root filesystem, healthcheck |
| `docker-compose.yml` | single-writer Compose deployment with a named state volume and loopback port |
| `systemd/vibeguard-approval.service` | hardened systemd unit with `StateDirectory`, restart and graceful stop |
| `kubernetes/vibeguard-approval.yaml` | Deployment/service/PVC/NetworkPolicy with readiness/liveness probes |
| `config/README.md` | users, signing keys and key generation |

## State

| Path | Contents |
|---|---|
| `/var/lib/vibeguard/approvals.json` | tickets, quorum state, used tokens, approver public keys |
| `/var/lib/vibeguard/approval-audit.jsonl` | signed approval audit chain |
| `/var/lib/vibeguard/approval-audit.jsonl.key.pem` | audit signing key (generated on first start if absent) |
| `/etc/vibeguard/` | users, signing keys, approval/identity private keys (read-only) |

The JSON store is **single-writer**. Use one replica and `Recreate` rollout. For
active-active HA, replace it with a transactional shared backend first.

## Run

```bash
# Build
docker build -f deploy/Dockerfile -t vibeguard-approval:1.16.0 .

# Configure deploy/config (not committed with real keys), then:
docker compose -f deploy/docker-compose.yml up -d
# The container runs as UID/GID 1000; ensure mounted config files are readable
# by that user (or use Docker secrets and point the env vars at them).
curl -fsS http://127.0.0.1:8787/health
curl -fsS http://127.0.0.1:8787/ready
```

Kubernetes: create the `vibeguard-approval-keys` Secret from `deploy/config`,
apply the manifest, and point the NetworkPolicy at your TLS ingress namespace.

## Monitoring

- `GET /health` — liveness.
- `GET /ready` — readiness; fails while shutting down or when the state
  directory is not writable.
- `GET /metrics` — Prometheus text; set `VIBEGUARD_APPROVAL_METRICS_TOKEN` to
  require a bearer token.
- JSON request logs go to stdout (request id, method, route, status, duration;
  never bodies, passwords or tokens).

See [docs/OPERATIONS.md](../docs/OPERATIONS.md) for alerts, backup/restore,
recovery and upgrade procedures.
