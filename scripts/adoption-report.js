'use strict';

/*
 * scripts/adoption-report.js — public adoption counters.
 *
 * Fetches only public npm/GitHub metadata. Stars and downloads are not quality
 * measures; they are context for whether anyone tried the release.
 *
 * Usage: node scripts/adoption-report.js [--json]
 */

const fs = require('fs');
const path = require('path');

const REPO = 'yagyeshVyas/VibeGuard';
const PACKAGE = '@yagyeshvyas/vibeguard';
const OUT_JSON = path.join(__dirname, '..', 'reports', 'adoption.json');
const OUT_MD = path.join(__dirname, '..', 'reports', 'adoption.md');

async function getJson(url) {
  const headers = { 'user-agent': 'vibeguard-adoption-report', accept: 'application/json' };
  if (process.env.GITHUB_TOKEN && url.includes('api.github.com')) headers.authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  const res = await fetch(url, { headers });
  if (!res.ok) throw new Error(`${url} -> ${res.status}`);
  return res.json();
}

function enc(value) { return encodeURIComponent(value); }

async function main() {
  const [repo, registry, week, month] = await Promise.all([
    getJson(`https://api.github.com/repos/${REPO}`),
    getJson(`https://registry.npmjs.org/${enc(PACKAGE)}`),
    getJson(`https://api.npmjs.org/downloads/point/last-week/${enc(PACKAGE)}`),
    getJson(`https://api.npmjs.org/downloads/point/last-month/${enc(PACKAGE)}`),
  ]);
  const latest = registry['dist-tags'] && registry['dist-tags'].latest;
  const report = {
    generatedAt: new Date().toISOString(),
    package: PACKAGE,
    latestVersion: latest || null,
    github: {
      stars: repo.stargazers_count,
      forks: repo.forks_count,
      watchers: repo.subscribers_count,
      openIssues: repo.open_issues_count,
      description: repo.description,
      url: repo.html_url,
    },
    npm: {
      lastWeekDownloads: week.downloads || 0,
      lastMonthDownloads: month.downloads || 0,
    },
    interpretation: 'Stars/downloads measure attention only. The useful signal is a reproducible report from a non-maintainer on their own code.',
  };
  fs.mkdirSync(path.dirname(OUT_JSON), { recursive: true });
  fs.writeFileSync(OUT_JSON, JSON.stringify(report, null, 2) + '\n');
  const md = [
    '# Adoption Snapshot',
    '',
    `Generated: ${report.generatedAt}`,
    '',
    '| Metric | Value |',
    '|---|---:|',
    `| GitHub stars | ${report.github.stars} |`,
    `| GitHub forks | ${report.github.forks} |`,
    `| Open issues | ${report.github.openIssues} |`,
    `| npm latest | ${report.latestVersion || 'unknown'} |`,
    `| npm downloads, last week | ${report.npm.lastWeekDownloads} |`,
    `| npm downloads, last month | ${report.npm.lastMonthDownloads} |`,
    '',
    report.interpretation,
    '',
    'Independent feedback process: [docs/ADOPTION.md](../docs/ADOPTION.md).',
  ].join('\n') + '\n';
  fs.writeFileSync(OUT_MD, md);
  if (process.argv.includes('--json')) process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  else {
    process.stdout.write(`stars=${report.github.stars} forks=${report.github.forks} npm=${report.latestVersion} downloads/week=${report.npm.lastWeekDownloads}\n`);
    process.stdout.write(`report: ${path.relative(path.join(__dirname, '..'), OUT_MD)}\n`);
  }
}

main().catch((err) => { process.stderr.write(`adoption report failed: ${err.message}\n`); process.exit(1); });
