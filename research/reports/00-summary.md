# NASA OSS Supply-Chain Security Audit — Findings Summary

**Audit window:** single session, 2026-05-14
**Scope:** GitHub Actions workflows + git history of 18 public NASA repositories across `nasa/`, `nasa-jpl/`, `NASA-AMMOS/` orgs
**Methodology:** static analysis only (zizmor 1.24.1, trufflehog 3.95.3, manual review); **zero traffic to nasa.gov**; no exploit execution
**Reportable channel:** NASA VDP (https://bugcrowd.com/nasa-vdp) or directly on the affected repos as security advisory

## Repos covered

| Org | Repo | Workflows | Trufflehog (full) |
|---|---|---:|---:|
| nasa | trick | 15 | 0 verified |
| nasa | cFS | 16 | 0 verified |
| nasa | cFE | 11 | 0 verified |
| nasa | osal | 9 | 0 verified |
| nasa | fprime | 27 | 0 verified |
| nasa | openmct | 8 | 0 verified |
| nasa | astrobee | 6 | 0 verified |
| nasa | cumulus | 2 | 0 verified |
| nasa | earthdata-search | 3 | 0 verified |
| nasa | apod-api | 0 | 0 verified |
| nasa | nos3 | 1 | 0 verified |
| nasa-jpl | ION-DTN | 27 | 0 verified |
| nasa-jpl | explorer-1 | 8 | 0 verified |
| nasa-jpl | mango-ui | 1 | 0 verified |
| NASA-AMMOS | MMGIS | 5 | 0 verified |
| NASA-AMMOS | AIT-Core | 2 | 0 verified |
| NASA-AMMOS | AIT-GUI | 0 | 0 verified |
| NASA-AMMOS | aerie-cli | 2 | 0 verified |
| NASA-AMMOS | plandev-ui | 5 | 0 verified |

## Findings index

| # | ID | Severity | Repo(s) | Class |
|---|---|---|---|---|
| 1 | NASA-WF-001 | **High** | nasa-jpl/ION-DTN (15 workflows) | Self-hosted-runner + expression injection (shell + github-script) |
| 2 | NASA-WF-002 | Medium | nasa/trick (3 workflows) | `workflow_run` without explicit permissions + unpinned third-party action |
| 3 | NASA-WF-003 | Medium | nasa/trick (`brew_tests.yml` + `publish_commit.yml`) | Bottle-artifact poisoning chain gated by maintainer label |
| 4 | NASA-WF-004 | Low/Medium | nasa/cFE, nasa/cFS, nasa/osal | Reusable workflow called via mutable `@dev` ref with `secrets: inherit` |
| 5 | NASA-WF-005 | Low | Multiple | 596 unpinned `uses:` references (`@v1`, `@v2`, `@main`) across audited repos |

No verified secret leaks discovered. No dependency confusion candidates (all `@nasa-jpl/*` npm scopes are claimed on the public registry).

See per-finding writeups in `01-iondtn.md`, `02-trick-workflow-run.md`, `03-trick-bottle.md`, `04-cfs-reusable-dev-ref.md`.

## Caveats

- Shallow clones (`depth=1`) limit secret-scan history coverage. A full-history rescan on `nasa/cumulus` is recommended (currently in progress, results pending at time of writeup).
- "High confidence" template-injection from reusable-workflow `inputs.*` is not directly exploitable by external attackers unless a caller forwards untrusted (PR-fork) data. I traced the obvious callers; a comprehensive caller graph requires deeper analysis.
- Self-hosted-runner findings on ION-DTN are flagged High because of *blast radius* (persistence on JPL CI). Direct external reachability still needs upstream caller tracing — see writeup.
- This audit only looked at workflows + git history. Application source code, deployed services, and supply-chain (npm deps with CVEs) were not in scope.

## Recommendations (high-level)

1. **ION-DTN:** quote all `${{ inputs.* }}` shell interpolations (`"${INPUT}"` via env, never raw `${{ }}` in `run:`) and switch github-script bodies to read inputs from `process.env`. Audit upstream callers of `ci-workflow-*.yml` to confirm no PR-fork data is forwarded.
2. **trick:** add explicit `permissions:` block (read-only by default) to all `workflow_run` workflows; pin `dorny/test-reporter` to a commit SHA.
3. **trick bottle chain:** require a re-build of bottles inside the `publish_commit.yml` flow rather than re-using PR-built artifacts; or require multiple maintainer approvals for the `pr-pull` label.
4. **cFE/cFS/osal:** pin `add-to-project-reusable.yml@dev` reference to a commit SHA. Consider moving the reusable to a dedicated `.github` repo with stricter branch protection.
5. **Org-wide:** enable Dependabot for GitHub Actions to auto-PR pinned-SHA updates.
