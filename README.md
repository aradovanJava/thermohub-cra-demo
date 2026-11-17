# ThermoHub – Breaking the Build

**Retrofitting OWASP Top 10:2025 for Cyber Resilience Act compliance – demo project**
Cyber Security Day 2026 · Java 21 · Spring Boot 4.1 · Maven · IntelliJ IDEA

ThermoHub is the cloud back end of a smart thermostat – a *remote data processing solution* of a
product with digital elements, so it is in scope of the EU Cyber Resilience Act (Regulation (EU) 2024/2847).
The repository contains the same product twice:

| Module | What it is | Expected result |
|---|---|---|
| `thermohub-legacy` | The product as shipped in 2019. One deliberate weakness per OWASP Top 10:2025 category. **Never deploy.** | 0 of 16 CRA checks met, build gates red |
| `thermohub-cra` | The same API, retrofitted for CRA Annex I | 16 of 16 checks met, build gates green |
| `cra-conformance-suite` | OWASP attacks as JUnit tests, each traced to a CRA requirement with `@CraRequirement` | runs against both |

Both apps expose the same HTTP API, so the **same attack** (IntelliJ HTTP Client, `http/demo.http`) and the
**same conformance suite** run against both – red on the left, green on the right.

---

## Quick start in IntelliJ IDEA

1. **File → Open…** → select this folder → *Open as Project* (Maven import runs automatically). Project SDK: **Java 21**.
2. Run configurations are shared in `.run/` and appear in the toolbar:

| # | Run configuration | What happens |
|---|---|---|
| 1 | `ThermoHub LEGACY :8080` | starts the vulnerable product |
| 2 | `ThermoHub CRA :8081 (demo profile)` | starts the retrofitted product with demo accounts |
| 3 | `CRA conformance - LEGACY (expect RED)` | 16 attacks, 16 red tests, report in `thermohub-legacy/target/` |
| 4 | `CRA conformance - CRA (expect GREEN)` | same 16 attacks, all green |
| 5 | `Gate SAST - LEGACY (expect BUILD FAILURE)` | SpotBugs + Find Security Bugs breaks the build |
| 6 | `Gate FULL - CRA (expect BUILD SUCCESS)` | tests + conformance + SAST + SBOM |
| 7 | `SBOM - both products` | CycloneDX `target/bom.json` for both |

3. Open `http/demo.http`, choose the environment **legacy** or **cra** in the editor toolbar, and run each
   request against both products.

### The same from the command line

```bash
mvn verify                                                         # default build (legacy suite excluded)
mvn -pl thermohub-legacy -am test -Pcra-gate                       # conformance suite vs legacy  -> RED
mvn -pl thermohub-legacy -am verify -DskipTests -Pcra-sast         # SAST gate vs legacy          -> BUILD FAILURE
mvn -pl thermohub-cra    -am verify -Pcra-gate                     # everything vs CRA app       -> BUILD SUCCESS
mvn package -DskipTests -Pcra-sbom                                 # SBOMs in */target/bom.json

trivy sbom thermohub-legacy/target/bom.json --severity HIGH,CRITICAL   # CVE-2022-1471 (SnakeYAML 1.33)
semgrep scan --config .semgrep/cra-rules.yml thermohub-legacy          # 13 findings, each mapped to CRA
gitleaks dir thermohub-legacy --config .gitleaks.toml                  # 2 committed secrets
```

### Maven profiles (quality gates)

| Profile | Gate | CRA reference |
|---|---|---|
| `cra-sast` | SpotBugs + Find Security Bugs, SECURITY category only, `failOnError` | Annex I Part II (3) |
| `cra-sbom` | CycloneDX SBOM (JSON + XML) | Annex I Part II (1) |
| `cra-gate` | both of the above; also enables the conformance suite in the legacy module | Annex I Part I + Part II |

---

## Demo credentials (public, demo only)

| User | Legacy (8080) | CRA app, `demo` profile (8081) |
|---|---|---|
| alice (owns device 1) | `summer2026` | `Mint-Kettle-Orbit-2026` |
| bob (owns device 2) | `123456` | `Copper-Lantern-Tide-2026` |
| admin | `admin` (factory default!) | `Granite-Harbor-Echo-2026` |

The CRA app has **no default credentials**: without the `demo` profile it refuses to start until
`THERMOHUB_ADMIN_PASSWORD` (>= 15 characters, not on the deny list, not containing the user name) and
`THERMOHUB_CRYPTO_WIFI_KEY` (Base64, 256 bit) are set. The demo passphrases are allow-listed in
`.gitleaks.toml` with a justification – that is what a documented exception looks like.

The pairing code of the unpaired thermostat `TH-0003` is generated at start-up and printed in the CRA
app's log (`DEMO: pairing code for TH-0003 is ...`).

### Signed firmware live demo (optional, A08)

```bash
java tools/FirmwareSigner.java keygen               # prints THERMOHUB_FIRMWARE_PUBLIC_KEY=...
# add that variable to run configuration 2 and restart the CRA app
java tools/FirmwareSigner.java image 2.5.0 fw-2.5.0.bin
java tools/FirmwareSigner.java sign 2.5.0 fw-2.5.0.bin   # prints X-Firmware-Signature
```
Put the signature into `http/http-client.private.env.json` (git-ignored) as `firmwareSignature` under the
`cra` environment and run the "signed firmware" request. Then change one byte of `fw-2.5.0.bin` and run it again.

---

## OWASP Top 10:2025 → CRA Annex I

| OWASP Top 10:2025 | Legacy weakness | CRA requirement | Retrofit | Gate that catches it |
|---|---|---|---|---|
| A01 Broken Access Control | IDOR on `/api/devices/{id}` | I (2)(d) | owner in the WHERE clause, 404, audit event | conformance test |
| A02 Security Misconfiguration | all actuator endpoints public, headers off | I (2)(b),(j) | health/info only, deny by default, headers on | conformance, Semgrep, ZAP |
| A03 Software Supply Chain Failures | SnakeYAML 1.33 (CVE-2022-1471) | I (2)(a); II (1),(2) | BOM-managed 2.x + SafeConstructor + allowlist | SBOM + Trivy, Semgrep, conformance |
| A04 Cryptographic Failures | MD5 passwords, `java.util.Random`, hard-coded AES/ECB key | I (2)(e) | bcrypt, SecureRandom, AES-256-GCM, injected key | FindSecBugs, Semgrep, gitleaks |
| A05 Injection | string-built SQL in search | I (2)(a),(e) | bind parameters + domain primitive | FindSecBugs, Semgrep, conformance |
| A06 Insecure Design | 95 °C setpoint, 4-digit pairing code w/o limit | I (1); Art. 13(2) | invariants in the model, 40-bit code, 5 tries/15 min | conformance |
| A07 Authentication Failures | admin/admin, unlimited guessing | I (2)(b),(d) | no defaults, policy at start-up, lockout | conformance, unit test |
| A08 Software or Data Integrity Failures | unsigned firmware roll-out | I (2)(f); II (7) | Ed25519 signature, anti-rollback, attestations | conformance, release workflow |
| A09 Security Logging & Alerting Failures | CRLF log forging, no security events | I (2)(l); Art. 14 | ECS JSON logs, audit events, metrics | conformance, Semgrep |
| A10 Mishandling of Exceptional Conditions | fail-open policy, stack traces to clients | I (2)(d),(j),(k) | parse once, default deny, RFC 9457 errors | conformance, Semgrep |
| (CRA process) | no reporting contact | II (5),(6) | `/.well-known/security.txt`, `SECURITY.md` | conformance |

More detail in [`docs/cra/owasp-cra-mapping.md`](docs/cra/owasp-cra-mapping.md).

## Repository map

```
.github/workflows/cra-pipeline.yml   PR + nightly: build, conformance, SAST, SBOM, SCA, secrets, Semgrep, DAST
.github/workflows/release.yml        tag: full gate, SLSA provenance + SBOM attestations, release assets
.github/dependabot.yml               updates "without delay" (Annex I Part II (2))
.semgrep/cra-rules.yml               11 organisation rules with OWASP + CRA metadata
.gitleaks.toml                       secret scanning incl. Spring properties rule
config/spotbugs/                     SAST include filter + documented risk acceptances
docs/cra/                            mapping, risk assessment, vulnerability handling, Annex VII outline
http/demo.http                       live attacks for IntelliJ's HTTP Client
tools/FirmwareSigner.java            single-file signing tool for the A08 demo
DEMO-SCRIPT.md                       minute-by-minute runbook for the talk
SECURITY.md                          coordinated vulnerability disclosure policy
```

## What was verified when this repository was produced

Verified in a sandbox with JDK 21: all framework-free security classes (setpoint, search term, command
parsing and policy, attempt limiter, password policy, token generator, AES-GCM cipher, firmware
verifier) compile and pass 41 behavioural checks; the firmware signing tool round-trips with the verifier;
all Java files parse; the Semgrep rules report 13 findings on legacy and 0 on the CRA module; gitleaks reports
2 leaks on legacy and 0 on the CRA module; all POM/XML/YAML files are well-formed.

**Not verified:** the Maven build itself (Maven Central was not reachable from the sandbox), so Spring
wiring, the full conformance run, SpotBugs results and Trivy results have not been executed yet.
**Do a full dry run on your machine before the talk** – see the checklist in `DEMO-SCRIPT.md`.
If Spring Boot 4.2 is out by then, bump `<version>` of the parent and re-run the gates: that is the
CRA's "remediate without delay" in practice.
