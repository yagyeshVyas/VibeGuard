# Contributing to VibeGuard

## The false-positive contract

`test/fixtures/clean/` contains realistic SAFE code. It MUST always scan to zero findings.
Every new rule MUST have a safe counterpart added to the clean fixture in the same PR.

If a PR breaks the clean fixture, it is blocked.

## Adding a rule

1. Add the rule to the appropriate array in `src/rules.js` (or `src/rules-pack.js` for extended packs)
2. Add a test in `test/run.js` that triggers the rule
3. Add a SAFE counterpart to `test/fixtures/clean/` that does NOT trigger the rule
4. Run `npm test` — all tests must pass including the clean fixture
5. Add the rule to the registry in `allRules()` if it lives in a separate module

### Rule shape

```js
{
  id: 'category.rule-name',
  severity: 'critical', // critical | high | medium | low
  confidence: 'high',   // high | medium | low
  title: 'Short title',
  re: /pattern/g,       // regex with global flag
  skipComments: true,   // skip comment lines (except secrets)
  message: 'What is wrong and why it is dangerous',
  fix: 'How to fix it',
}
```

### Design principles

1. **Low false positives over high recall.** We would rather MISS a fuzzy case than cry wolf on a safe one.
2. **Every rule is deliberately narrow.** Use `filter` functions to skip placeholders, BaaS keys, and known-safe patterns.
3. **Honest confidence tiers.** `high` = mechanical match. `medium` = strong heuristic. `low` = "review this" hint.
4. **Low-confidence findings count one tier lower** in grading. A single heuristic hint never tanks an otherwise clean project.
5. **Zero runtime dependencies** for the scanner. AST mode is optional (acorn in optionalDependencies).

## Running tests

```bash
npm test          # 63 tests, zero deps
npm run lint      # eslint
npm run coverage  # c8 coverage report
```

## Running the scanner on itself

```bash
npm run scan      # uses .vibeguardrc.json to skip src/ and test/
```
