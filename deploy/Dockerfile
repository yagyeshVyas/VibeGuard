# syntax=docker/dockerfile:1
#
# VibeGuard approval service image. Build from the repository root:
#   docker build -f deploy/Dockerfile -t vibeguard-approval:1.15.0 .
#
# The container is non-root, read-only at runtime, and keeps all mutable state
# under /var/lib/vibeguard. TLS is terminated by a reverse proxy in front of it.

FROM node:22-bookworm-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts

FROM node:22-bookworm-slim
ENV NODE_ENV=production \
    VIBEGUARD_APPROVAL_HOST=0.0.0.0 \
    VIBEGUARD_APPROVAL_PORT=8787 \
    VIBEGUARD_APPROVAL_ALLOW_REMOTE=1 \
    VIBEGUARD_APPROVAL_STORE=/var/lib/vibeguard/approvals.json \
    VIBEGUARD_APPROVAL_AUDIT=/var/lib/vibeguard/approval-audit.jsonl \
    VIBEGUARD_APPROVAL_USERS=/etc/vibeguard/users.json \
    VIBEGUARD_APPROVAL_SIGNING_KEYS=/etc/vibeguard/signing-keys.json \
    VIBEGUARD_APPROVAL_KEY=/etc/vibeguard/approval-private.pem \
    VIBEGUARD_APPROVAL_IDENTITY_KEY=/etc/vibeguard/identity-private.pem

WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY --chown=node:node package.json package-lock.json ./
COPY --chown=node:node bin ./bin
COPY --chown=node:node src ./src

RUN install -d -o node -g node -m 0700 /var/lib/vibeguard
USER node
EXPOSE 8787
VOLUME ["/var/lib/vibeguard"]

HEALTHCHECK --interval=15s --timeout=4s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:8787/ready').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

ENTRYPOINT ["node", "bin/cli.js", "approval"]
CMD ["serve"]
