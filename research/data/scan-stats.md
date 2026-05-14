# Scanner output summary (raw JSON not committed)

## zizmor (NASA flagship + sub-org)

| Rule | nasa/* | nasa-jpl + AMMOS |
|---|---:|---:|
| unpinned-uses | 382 | 214 |
| template-injection | 289 | 327 |
| excessive-permissions | 253 | 79 |
| artipacked | 134 | 60 |
| anonymous-definition | 81 | 51 |
| concurrency-limits | 48 | 45 |
| github-env | 17 | 0 |
| undocumented-permissions | 16 | 23 |
| secrets-outside-env | 13 | 15 |
| dangerous-triggers | 10 | 0 |
| unpinned-images | 8 | 1 |
| dependabot-cooldown | 4 | 2 |
| secrets-inherit | 4 | 1 |
| self-hosted-runner | 2 | 17 |
| superfluous-actions | 2 | 1 |
| use-trusted-publishing | 2 | 0 |
| cache-poisoning | 0 | 5 |

Total findings: ~1265 + ~850 (most are hygiene, not exploitable).

## trufflehog (verified-only, per repo)

Verified secret leaks across 18 audited repos + full-history rescan of `nasa/cumulus` and `nasa/apod-api`: **0**.

Unverified candidates in cumulus full-history scan: 59 `SnykKey` (UUID test fixtures) + 4 `Box` (package-lock.json integrity hashes). All confirmed false positives by Trufflehog's live verification step.

## Dependency confusion

Internal-looking scoped npm packages found in `NASA-AMMOS/plandev-ui` and `nasa-jpl/mango-ui`:
- @nasa-jpl/aerie-actions
- @nasa-jpl/aerie-ampcs
- @nasa-jpl/aerie-sequence-languages
- @nasa-jpl/seq-json-schema
- @nasa-jpl/stellar
- @nasa-jpl/stellar-react
- @nasa-jpl/stellar-svelte

All 7 are claimed and published on the public npm registry. **No dependency-confusion candidates.**
