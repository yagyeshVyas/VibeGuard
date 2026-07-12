## Summary

<!-- Brief description of what this PR changes and why -->

## Type of change

- [ ] Bug fix (false positive / false negative fix)
- [ ] New rule
- [ ] New feature / command
- [ ] Documentation update
- [ ] Refactor / cleanup

## The false-positive contract

> `test/fixtures/clean/` contains realistic SAFE code. It MUST always scan to zero findings.
> Every new rule MUST have a safe counterpart added to the clean fixture in the same PR.

- [ ] If I added a new rule, I added a SAFE counterpart to `test/fixtures/clean/`
- [ ] If I modified an existing rule, I verified the clean fixture still scans to zero

## Testing

- [ ] `npm test` passes (342 tests)
- [ ] `npm run lint` has 0 errors
- [ ] `npm run benchmark` — F1 did not drop

## Checklist

- [ ] My code follows the style guide (zero new runtime dependencies)
- [ ] I added tests for my changes
- [ ] I updated the docs if needed