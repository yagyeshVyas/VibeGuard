# Data Story Plan: "I scanned N open-source vibe-coded apps"

## Concept
Run VibeGuard against publicly available apps built with AI coding tools (Lovable, Bolt, Cursor, Claude Code) and publish the aggregate findings. This creates a credible data story that validates the tool and raises awareness about AI-generated code security.

## Step 1: Collect repos

### Sources
- GitHub search: `topic:lovable` `topic:bolt.new` `topic:cursor` `topic:vibecoding`
- GitHub API: search repos created in last 6 months with < 100 stars (indicates personal/hobby projects)
- Filter: must have `package.json` (JS/TS projects only for now)
- Target: 50-100 repos

### Ethical considerations
- Only scan public repos (already publicly visible)
- Do NOT publish repo names or author names in the aggregate report
- If you find LIVE secrets (active API keys), responsible disclosure FIRST (see Step 4)
- Do NOT scan private repos or repos with explicit "no scraping" signals

### Collection script (to build)
```bash
# Pseudocode
gh search repos --topic=lovable --language=TypeScript --limit=100 --json fullName,url > repos.json
# Clone each, run vibeguard scan --json, collect results
```

## Step 2: Batch scan

```bash
for repo in repos/*.json; do
  vibeguard scan $repo --json --no-deps >> results.jsonl
done
```

Or build a simple batch runner script that:
1. Clones each repo to a temp dir
2. Runs `vibeguard scan --json`
3. Collects findings into a single JSONL file
4. Cleans up the clone

## Step 3: Aggregate stats

Metrics to report:
- % of repos with at least 1 CRITICAL finding
- % with hardcoded secrets (by type: OpenAI, Stripe, AWS, GitHub, etc.)
- % with open databases (Supabase no RLS, Firebase open rules)
- % with SQL injection (template literal + req.body)
- % with XSS (dangerouslySetInnerHTML, innerHTML, v-html)
- % with AI-specific issues (prompt injection, LLM output to exec)
- Average findings per repo
- Most common rule IDs fired

## Step 4: Responsible disclosure

### For LIVE secrets (active API keys):
1. Do NOT include in the published report
2. Check if the key is active: `vibeguard scan --verify-keys` (opt-in, pings the provider)
3. If active: contact the repo owner via GitHub Security Advisory or email
4. Give 90 days to rotate before publishing any stats that could identify the repo
5. Report to the provider (OpenAI, Stripe, AWS) if the owner doesn't respond

### For open databases:
1. Check if the database is publicly accessible (try the URL)
2. If accessible: contact the owner immediately
3. Do NOT publish database URLs or project names

### Publication guidelines:
- Aggregate stats only — no repo names, no author names, no URLs
- If a specific finding is noteworthy, get permission from the owner first
- Redact all secrets, even expired ones
- Include a "methodology" section explaining how data was collected

## Step 5: Blog post structure

1. **Hook:** "I scanned 50 apps built with AI coding tools. X% had exposed secrets."
2. **Methodology:** How repos were collected, how scanning was done, what was excluded
3. **Results:** Charts (bar charts for % by category, pie chart for secret types)
4. **Examples:** 3-4 anonymized code snippets showing common patterns
5. **Comparison:** How do these numbers compare to non-AI-generated code? (Cite academic studies if available)
6. **Recommendations:** What AI tool makers should do, what developers should do
7. **Limitations:** Self-built scanner, JS/TS only, small sample, selection bias
8. **Call to action:** Run `npx @yagyeshvyas/vibeguard scan` on your project

## Timeline
- Week 1: Collect repos, build batch runner
- Week 2: Run scans, aggregate stats, verify any live secrets
- Week 3: Responsible disclosure (if needed), write blog post
- Week 4: Publish, submit to HN/Reddit/Twitter

## Tools needed
- GitHub CLI (`gh`) for repo search
- Simple bash/Node script for batch scanning
- A charting library (or just matplotlib/Excel) for the stats
- VibeGuard itself (`npx @yagyeshvyas/vibeguard scan --json`)