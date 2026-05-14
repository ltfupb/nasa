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

Unverified candidates in `nasa/cumulus` full-history scan (93 total, all false positives or intentional test fixtures, none verified live):

| Detector | Count | Disposition |
|---|---:|---|
| SnykKey | 68 | UUID strings in Snyk-bot–authored commits and lockfiles (not real Snyk API keys; verification returned 403) |
| FTP | 7 | `ftp://testuser:testpass@127.0.0.1` in `bamboo/bootstrap-unit-tests.sh` and `travis-ci/start-local-services.sh` — localhost test loopback |
| Box | 7 | `package-lock.json` integrity hashes that coincidentally match the Box token regex |
| PrivateKey | 5 | RSA keys in `packages/test-data/keys/*.pem` and `packages/ingest/test/fixtures/ssh_client_rsa_key` — explicit test fixtures |
| Circle | 4 | Hex strings in commit metadata and `README.md` (verification 403) |
| Dockerhub | 2 | UUIDs in `app/views/docs.md` documentation |

The committed test RSA keys are a *very* minor hygiene note: while clearly labeled as test fixtures, public test keys can become real-world keys the moment they're reused for any bootstrap (e.g., a localstack instance exposed to the internet). Standard remediation is to generate ephemeral test keys in CI rather than commit them. Not VDP-reportable.

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
