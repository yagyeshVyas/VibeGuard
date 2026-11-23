# Adoption and Independent Feedback

VibeGuard is an internal-testing release. Adoption is measured by whether
developers can install it, run it on their own repository, and tell us where it
worked, failed or violated their trust. This page defines that process so the
feedback is real, attributable and useful.

## 10-minute independent evaluation

Use a repository you own and did not build VibeGuard for.

```bash
npx -y @yagyeshvyas/vibeguard@1.14.0 scan .
npx -y @yagyeshvyas/vibeguard@1.14.0 scan . --json
```

Then try one of:

```bash
npx -y @yagyeshvyas/vibeguard@1.14.0 sandbox verify
npx -y @yagyeshvyas/vibeguard@1.14.0 approval serve --help
npx -y @yagyeshvyas/vibeguard@1.14.0 sandbox "const x = 1 + 1; x" --isolation os
```

Report:

1. OS, Node version, install method and command.
2. Time to first result, and anything that blocked installation.
3. One useful finding, one false positive and one false negative you can
   identify in your own code.
4. Whether the permission, network, telemetry and approval claims match what
   you observed.
5. The documentation or CLI step that was most confusing.

Open the **independent feedback** issue form or reply to the pinned GitHub
Discussion. Do not send live secrets; redact before posting.

## What counts as independent

- You have not contributed code, policy or review to this repository.
- You used your own repository, not the benchmark fixtures.
- You disclose any commercial or personal relationship with the maintainer.
- You choose whether we may quote you (named, anonymised, or not at all).

We do not pay for reviews, trade stars, or publish invented testimonials. If
feedback cannot be attributed, it is recorded as an aggregate observation only.

## How feedback is handled

| Step | Action |
|---|---|
| Triage | `feedback`/`independent-review` label, severity and reproducibility checked |
| Confirm | Maintainer attempts a local reproduction; asks for redacted evidence |
| Fix or document | Regression test for bugs; limitation/known-issue entry for accepted gaps |
| Publish | Release note or audit report; no silent edits to benchmark claims |
| Close | Reporter informed; permission recorded for any quotation |

Security vulnerabilities go through [SECURITY.md](../.github/SECURITY.md), not a
public issue.

## Channels

- **GitHub Discussion** — pinned “Independent developer feedback wanted”.
- **Issue form** — `.github/ISSUE_TEMPLATE/independent-feedback.yml`.
- **Security** — private advisory per `SECURITY.md`.
- **Package** — `@yagyeshvyas/vibeguard` on npm.

## Adoption metrics we track

- npm downloads for the last week/month (not a quality measure).
- GitHub stars, forks and non-maintainer issue/discussion authors.
- Reproductions of the pinned external benchmark on a second machine/OS.
- Independent reports that survive reproduction and become regression tests.
- Support burden: repeated install/doc failures, time to first result.

Run `npm run adoption:report` for a dated public snapshot. Stars and downloads are vanity-adjacent. The useful adoption signal is a
non-maintainer running the tool on their own code and either filing a
reproducible bug or stating that a limitation was not disclosed.

## Outreach status

The launch drafts in [`launch/`](../launch/) are copy-paste assets, not proof of
publication. A channel counts only after the maintainer posts it from the
maintainer account; automated mass-posting is not performed.
