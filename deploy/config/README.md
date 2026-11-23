# Approval service configuration

Mount this directory (or a Kubernetes Secret) at `/etc/vibeguard` read-only.
All files are secrets or key material; use mode `0600` (Kubernetes Secret:
`0440` for the group that runs the pod).

## users.json

```json
{
  "human:acme/alice@example.com": {
    "passwordHash": "scrypt$16384$8$1$<salt>$<hash>",
    "displayName": "Alice"
  }
}
```

Generate a hash without putting the password in shell history:

```bash
read -r -s VG_APPROVAL_PASSWORD
export VG_APPROVAL_PASSWORD
vibeguard approval hash-password
unset VG_APPROVAL_PASSWORD
```

## signing-keys.json

Maps each human principal to an Ed25519 private key used by the service to sign
the `VGAPPROVER` proof after the human authenticates.

```json
{
  "human:acme/alice@example.com": "/etc/vibeguard/alice.pem"
}
```

Generate keys:

```bash
openssl genpkey -algorithm ED25519 -out alice.pem
openssl genpkey -algorithm ED25519 -out approval-private.pem
openssl genpkey -algorithm ED25519 -out identity-private.pem
chmod 600 *.pem
```

`approval-private.pem` signs the final `VGAPPROVAL` token.
`identity-private.pem` issues short-lived agent/human VGAT tokens via
`vibeguard approval issue`.

## Rotation

Rotate a human key through `POST /approval/keys` with an admin token that has
`approval.admin`, or update `signing-keys.json` and restart during a maintenance
window. Existing approval tokens remain valid until expiry; the signed audit
records the rotation.
