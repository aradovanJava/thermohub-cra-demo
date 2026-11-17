# Live demo runbook – "Breaking the Build" (60 min)

Slide numbers refer to `Breaking-the-Build_CSD2026.pptx`. Total live demo time ≈ 20 minutes,
spread over the talk. Every demo step has a fallback (screenshot or test output) in case the network or a
port misbehaves.

## T-60 min: pre-flight checklist

- [ ] `mvn -q -DskipTests install` at the root (warms the Maven cache; no downloads on stage)
- [ ] Run configuration **3** once – the legacy pairing brute force takes ~10–20 s; know the timing
- [ ] Run configuration **4** once – must be 16/16 green. If anything is red, fix before the talk
- [ ] `trivy sbom thermohub-legacy/target/bom.json` once (downloads the vulnerability DB in advance)
- [ ] GitHub: open the latest `CRA pipeline` run in a browser tab (legacy jobs red, CRA jobs green)
- [ ] Start run configurations **1** (legacy :8080) and **2** (CRA :8081)
- [ ] Copy the line `DEMO: pairing code for TH-0003 is ....` from the CRA console into a note
- [ ] Delete `PWNED-by-yaml.txt` from the project root if it exists
- [ ] IntelliJ: Presentation Mode font ≥ 20 pt, HTTP Client response viewer docked to the right
- [ ] Open `http/demo.http`; environment selector visible in the editor toolbar
- [ ] Close Slack, mail, notifications

## Timeline

| Time | Slides | What you do | What the audience sees |
|---|---|---|---|
| 0:00 | 2–4 | Talk (slide 1 is the holding slide) | Hook: Annex I Part I (2)(a), takeaways |
| 4:00 | 5–10 | Talk | Timeline, 24 h/72 h/14 d clock, scope, Annex I, penalties |
| 13:00 | 11–14 | Talk | OWASP Top 10:2025, the map, ThermoHub architecture |
| 17:00 | 15 | **DEMO A01** | `demo.http` → *A01*, env **legacy**: bob's thermostat. Switch to **cra**: 404. |
| 19:00 | 16 | **DEMO A02** | *A02* on legacy: `/actuator/env` shows `thermohub.mqtt.password`. On cra: 401. |
| 20:30 | 17 | **DEMO A03** | *A03* on legacy: `PWNED-by-yaml.txt` appears in the project tree. On cra: 400. Then run configuration **7** + `trivy sbom thermohub-legacy/target/bom.json` → CVE-2022-1471 CRITICAL. |
| 23:30 | 18–19 | **DEMO A05 → A04** | *A04 + A05* on legacy: usernames + MD5 hashes in the JSON. Paste `e10adc3949ba59abbe56e057f20f883e` into a search engine → "123456". On cra: 400. |
| 27:00 | 20 | **DEMO A06** | *A06 setpoint* 95 °C: legacy 200, cra 400. Brute force: show the red `a06_pairingCodeCannotBeBruteForced` result from config **3** ("paired after 4712 guesses"). Live on cra: send *A06 pairing* 6× → 429. |
| 29:00 | 21 | **DEMO A07** | *A07* `admin admin`: legacy 200, cra 401. Mention: cra refuses to *start* without a strong admin passphrase (`NoDefaultCredentialsTest`). |
| 30:00 | 22 | **DEMO A08** | *A08 unsigned*: legacy "rolled out to 3 thermostats", cra 400 – fail-closed ("no firmware signing key configured"; with `THERMOHUB_FIRMWARE_PUBLIC_KEY` set: "Firmware is not signed"). Optional: signed request (README). |
| 31:30 | 23 | **DEMO A09** | *A09 forge*: legacy console shows a fake "role ADMIN granted to mallory" line. cra: 400; then *A09 security events* on cra shows ACCESS_DENIED / PAIRING_THROTTLED events. |
| 33:00 | 24 | **DEMO A10** | *A10 fail-open*: `enable_debug_shell` → legacy 202 executed ENABLE_DEBUG_SHELL; upper-case version → 403 (the bug is in the error path). cra: 400. *A10 errors*: stack trace vs RFC 9457. |
| 35:00 | 25–26 | **DEMO suite** | Run configuration **3** (red, 0/16) and **4** (green, 16/16) side by side. Open `target/cra-conformance-report-*.md`. |
| 38:00 | 27 | **DEMO gates** | Run configuration **5**: BUILD FAILURE with Find Security Bugs findings (SQL injection, MD5, predictable random, hard-coded key, ECB ...). Run **6**: BUILD SUCCESS. Show the GitHub Actions tab: same picture in CI. |
| 42:00 | 28–31 | Talk | SBOM & vulnerability handling, velocity, gaps, roadmap |
| 51:00 | 32–34 | Talk | Takeaways, resources, Q&A |

## Fallbacks

- **Port in use** – change `server.port` in the run configuration (`-Dserver.port=9090`) and the host in `http-client.env.json`.
- **HTTP Client encoding problem with the A05 payload** – use curl:
  `curl -u alice:summer2026 -G --data-urlencode "q=%' UNION SELECT 0, role, username, password_hash, 'pwned', 0 FROM users -- " http://localhost:8080/api/devices/search`
- **Trivy not installed** – show the SCA job of the GitHub Actions run, or `semgrep scan --config .semgrep/cra-rules.yml thermohub-legacy`.
- **The CRA module goes red in SCA on the day** – great: a new CVE in a dependency appeared after release.
  Say so, bump the Spring Boot parent version, re-run. That is Annex I Part II (2) live.

## Reset between rehearsals

Restart both apps (in-memory H2, all state is reset). Delete `PWNED-by-yaml.txt`.
