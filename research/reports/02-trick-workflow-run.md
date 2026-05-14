# NASA-WF-002 — Trick: workflow_run reporters missing explicit permissions + unpinned action

**Repo:** https://github.com/nasa/trick
**Files:**
- `.github/workflows/report_linux.yml`
- `.github/workflows/report_linux_py2.yml`
- `.github/workflows/report_alt_linux_distros.yml`

**Severity:** Medium
**Class:** CWE-732 (Incorrect Permission Assignment for Critical Resource) + supply-chain risk via mutable action ref

## Where

All three files have the same shape:

```yaml
name: "Report Linux"
on:
  workflow_run:
    workflows: ["Linux"]   # the build workflow that produced the artifact
    types: [completed]
jobs:
  report:
    runs-on: ubuntu-latest
    steps:
      - uses: dorny/test-reporter@v2       # report_linux_py2.yml uses @v1
        with:
          artifact: Trick_${{matrix.cfg.os}}${{matrix.cfg.tag}}
          path: "*.xml"
          reporter: java-junit
```

There is **no `permissions:` block at workflow or job level.** Compare with the sibling `report_macos.yml` which correctly restricts itself:

```yaml
permissions:
  actions: read
  checks: write
```

## Why it's a bug

1. **Token scope inheritance.** A workflow without an explicit `permissions:` block falls back to the repository's default `GITHUB_TOKEN` scope. NASA's repo-level default *should* be read-only (this is GitHub's default for repos created after Feb 2023), but many older NASA repos predate that change. If the default is `read+write`, then this workflow's token has `contents: write`, `issues: write`, `pull-requests: write`, `pages: write`, etc.

2. **`workflow_run` runs with the BASE repo's secrets and write access**, *regardless* of whether the triggering build came from a fork PR. This is the standard `workflow_run` trap.

3. **`dorny/test-reporter@v2`** (and `@v1` in `report_linux_py2.yml`) is a **mutable tag reference**. If dorny's account is compromised or the tag is force-pushed to a malicious commit, every NASA workflow pinned to `@v1`/`@v2` executes attacker JS in the workflow_run context — i.e., with the base repo's token. Attacker actions: push to default branch, comment on PRs, modify GitHub Pages content, create releases, etc.

4. The action *downloads an artifact* uploaded by the triggering "Linux" workflow. That triggering workflow runs on `pull_request`, meaning a fork PR controls the artifact content. dorny/test-reporter parses JUnit XML — historically that's been a vector for XXE / path-traversal CVEs in JUnit parsers. The dorny action itself has had advisories in older versions; pinning to a SHA is the only defense.

## Why `report_macos.yml` is not affected

It has both:
- explicit `permissions: actions: read, checks: write` (downgrades the token)
- a matrix-pinned attempt-number in the artifact name, reducing artifact-substitution risk

The three vulnerable files are essentially "forgot to apply the same hardening."

## Recommended fix

For each of the three files, add at job level:

```yaml
jobs:
  report:
    runs-on: ubuntu-latest
    permissions:
      actions: read
      checks: write
      contents: read
      pull-requests: read
    steps:
      - uses: dorny/test-reporter@31a54ee7ebcacc03a09ea97a7e5465a47b84aea5  # v2.5.0
```

And mirror `report_macos.yml`'s artifact-name discipline (include `${{ github.event.workflow_run.run_attempt }}` so an attacker can't pre-poison the cache).

## Reporting

Submit alongside NASA-WF-001 to NASA VDP. The "no explicit permissions on workflow_run" pattern is a well-known anti-pattern; the report should reference GitHub's own guidance: https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#workflow_run
