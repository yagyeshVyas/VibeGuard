# Launch and feedback kit

These are copy-paste drafts, **not proof of publication**. A channel is counted
only after the maintainer posts from the maintainer account. Automated
mass-posting is not performed.

## Runbook

1. Confirm the release is live: `npm view @yagyeshvyas/vibeguard version` and
   GitHub release `v1.14.0`.
2. Post one channel at a time, from the maintainer account, with a link to the
   independent feedback form.
3. Do not buy stars, reviews or upvotes. Do not paraphrase a private reply into a
   public testimonial without permission.
4. Record the channel, URL, date and any resulting non-maintainer feedback in
   `docs/ADOPTION.md` or the GitHub Discussion.
5. Triage feedback with `feedback` and `independent-review` labels. Reproduce
   before fixing; add a regression test for every confirmed bug.

## Status

| Channel | Draft | Status |
|---|---|---|
| Hacker News (Show HN) | `show-hn.md` | Drafted — requires maintainer account |
| Reddit r/vibecoding | `reddit-post.md` | Drafted — requires maintainer account |
| GitHub Discussion | [Independent developer feedback wanted](https://github.com/yagyeshVyas/VibeGuard/discussions/23) | Open |
| GitHub issue form | `.github/ISSUE_TEMPLATE/independent-feedback.yml` | Open |
| MCP directories / awesome lists | Not submitted | Evaluate each list's contribution rules first |
| Dev.to / blog | Not drafted | Optional |

## Claims that must stay accurate

- 861 rules, 95 MCP tools, 18 languages, 654 tests, 50/50 platform tests.
  See [`docs/STATUS.md`](docs/STATUS.md) for current counts and evidence.
- Windows AppContainer verified on the audit host; macOS VM requires a guest
  image and is not live-verified in this repository.
- The external Juice Shop benchmark is a curated label set, not a
  representative precision/recall study.
- The 119/119 self-built corpus is saturated and is a regression gate.
- The independent security audit is an in-session review, not a certified
  external audit firm.

Update the drafts when a claim changes. Do not reuse old numbers from v1.7.
