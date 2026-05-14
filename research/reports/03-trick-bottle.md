# NASA-WF-003 — Trick: bottle-artifact poisoning chain (label-gated)

**Repo:** https://github.com/nasa/trick
**Files:**
- `.github/workflows/brew_tests.yml` (PR build)
- `.github/workflows/publish_commit.yml` (release publisher)

**Severity:** Medium (requires maintainer action) → could be High if `pr-pull` label is auto-applied or trivially granted
**Class:** CWE-494 (Download of Code Without Integrity Check) chained with CWE-863 (Incorrect Authorization)

## Attack chain

1. **`brew_tests.yml`** triggers on every `pull_request` touching `Formula/**`. It runs `brew install --build-from-source` and `brew bottle` on the PR-supplied Ruby formula. Homebrew formulas execute arbitrary Ruby in their `install` block — so any fork can run code in the ephemeral GitHub-hosted macOS runner. The job's permissions are read-only, so secrets are safe; but the resulting bottle tarball is uploaded as `bottles_${{ matrix.os }}` (line 89). **The bottle's contents are fully attacker-controlled** (the attacker can make `brew bottle` package whatever binary they like, e.g., a backdoored `trick` binary).

2. **`publish_commit.yml`** triggers on `pull_request_target` with type `labeled`, gated by `contains(github.event.pull_request.labels.*.name, 'pr-pull')`. When the label is applied:
   - The workflow runs in the base repo context, with `contents: write` and `pull-requests: write` permissions and full secrets.
   - It locates the most recent successful `brew_tests.yml` run for that PR branch (lines 53–67) and downloads the `bottles_<os>` artifacts (lines 69–78).
   - It uploads the (attacker-controlled) bottle tarballs to the NASA Trick GitHub Release (`gh release upload --clobber`, lines 87–106).
   - It then merges the PR branch into the primary tap branch and pushes (lines 110–123).

3. **End state:** the public NASA Trick release page hosts a tarball containing whatever payload the attacker stuffed into the bottle's `install` step. Anyone running `brew install nasa/trick/trick` afterwards fetches and executes it.

## What gates the attack

The `pr-pull` label must be applied by someone with `triage` (or higher) permission. Standard Homebrew tap practice is for maintainers to apply this label *after* reviewing the formula source — but:

- Review usually focuses on the formula `.rb` text, not on whether the bottle's `install` did the same thing it claims.
- The attack vector is the **artifact**, not the Ruby source. A formula whose `install` is benign in source can still produce a bottle whose contents are malicious if the attacker exploits any build-time hook (post-install, patches/, helper scripts) or modifies binaries during `brew test`.
- If the repo ever automates label application (e.g., a bot that labels formulas that pass certain criteria), this becomes preauth.

## Recommended fixes

1. **Do not trust the build artifact.** Have `publish_commit.yml` re-build bottles fresh from the formula source after merge, rather than downloading the PR's `brew_tests.yml` artifact.
2. **Verify bottle hashes** against the formula's declared `sha256` *before* `gh release upload --clobber`. (`brew bottle --json` already emits the hash; compare it to a deterministic build.)
3. **Require multiple maintainer approvals** for the `pr-pull` label — or move bottle publishing to a separate, manually-triggered `workflow_dispatch` flow with branch protection.
4. **Pin** `Homebrew/actions/setup-homebrew@main` and `Homebrew/actions/git-try-push@main` (currently mutable `@main` references) to commit SHAs.
5. Consider using `actions/attest-build-provenance` to sign published bottles, so downstream users can verify the bottle came from a sanctioned workflow run.

## Reporting

Worth submitting to NASA VDP. Frame the impact as "supply-chain compromise of `brew install nasa/trick/trick` users via a malicious PR that gets merged after label review focuses on source rather than artifact."
