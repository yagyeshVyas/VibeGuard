# AISVS-Style Control Mapping

This is an **internal readiness matrix**, not an AISVS 1.01 certification. It
maps the controls the repository actually implements to an AISVS-style set of
categories and cites verification evidence IDs.

Run:

```bash
vibeguard aisvs          # human summary
vibeguard aisvs --json   # machine-readable mapping
```

Status meanings:

- `implemented` — implemented and tested in the tested path.
- `partial` — only a mode/primitive; residual limitations exist.
- `not_verified` — no executable OS/platform evidence.
- `not_implemented` — no control.

Current summary from `src/platform/aisvs.js`: 12 partial, 1 not_verified, 2
not_implemented. No control is claimed as fully certified.

Evidence is in `research/SECURITY_TEST_MATRIX.md`; limitations are in
`research/KNOWN_LIMITATIONS.md`.
