# NASA-WF-004 — cFE / cFS / osal: reusable workflow called via mutable `@dev` ref

**Repos:**
- https://github.com/nasa/cFE
- https://github.com/nasa/cFS
- https://github.com/nasa/osal

**File pattern:** each repo's `.github/workflows/add-to-project.yml` contains:

```yaml
jobs:
  add-to-project:
    uses: nasa/cFS/.github/workflows/add-to-project-reusable.yml@dev
    secrets: inherit
```

**Severity:** Low–Medium (depends on dev-branch protection on `nasa/cFS`)
**Class:** CWE-829 (Inclusion of Functionality from Untrusted Control Sphere) — supply-chain via mutable ref

## Why

- `@dev` is a **branch reference**, not a commit SHA. Whoever can push to (or force-push to, or merge into) `nasa/cFS`'s `dev` branch can change the contents of the reusable workflow.
- `secrets: inherit` means every caller (cFE, cFS, osal) passes its full secret set to the reusable workflow. The reusable currently uses `secrets.ADD_TO_PROJECT_PAT` (a fine-grained GitHub PAT with project-board write scope), but `inherit` means *all* secrets become available — if any of these repos has additional secrets (deploy keys, release-publishing tokens), they're also reachable from the reusable.
- The triggers in each caller are `issues: [opened]` and `pull_request_target: [opened, ready_for_review, converted_to_draft]`. Both run **with secrets** and are reachable from anyone who can open an issue or fork-PR — which is "the world."
- Compromise vector: any time someone with `dev`-branch write modifies `add-to-project-reusable.yml` to include a malicious step, the next issue or PR opened on cFE/cFS/osal causes that malicious step to run with all three repos' secrets.

## The reusable workflow itself is currently safe

I read `add-to-project-reusable.yml@dev` (current head):
- Only uses `context.payload.pull_request.node_id` and `.number` (safe types).
- Does not interpolate PR body/title/head_ref into shell or JS.
- Uses `actions/add-to-project@v1.0.2` (version-pinned) and `actions/github-script@v7` (mutable).

So **no expression-injection sink exists today**. The risk is purely "tomorrow someone changes the reusable and accidentally introduces one, and the change goes live across three repos because they all chase `@dev`."

## Recommended fix

```yaml
jobs:
  add-to-project:
    uses: nasa/cFS/.github/workflows/add-to-project-reusable.yml@<commit-sha>
    secrets:
      ADD_TO_PROJECT_PAT: ${{ secrets.ADD_TO_PROJECT_PAT }}   # only what's needed; don't use `inherit`
```

Also enable Dependabot for GitHub Actions so SHA updates get auto-PRed and reviewed.

## Reporting

Low-priority on its own — frame as a defense-in-depth recommendation rather than an active vulnerability. NASA VDP accepts hygiene findings but usually prioritizes exploitable ones; consider opening an issue/PR on `nasa/cFS` directly instead.
