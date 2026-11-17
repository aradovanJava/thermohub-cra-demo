# OWASP Top 10:2025 → CRA Annex I mapping

How each OWASP risk category becomes evidence for an essential requirement of Regulation (EU) 2024/2847.
The mapping is a practitioner's mapping, not an official one: harmonised standards (EN 40000 series) and
Commission guidance take precedence once cited.

Legend – **Part I** = Annex I Part I (product properties), **Part II** = Annex I Part II (vulnerability handling).

| OWASP Top 10:2025 | Primary CRA requirement | Also supports | Engineering control (this repo) | Automated evidence |
|---|---|---|---|---|
| **A01** Broken Access Control (incl. SSRF) | Part I (2)(d) protection from unauthorised access | (2)(j) attack surface | Owner-scoped queries, deny-by-default filter chain, 404 for foreign ids | `a01_*` conformance test |
| **A02** Security Misconfiguration | Part I (2)(b) secure by default configuration | (2)(j) | Actuator health/info only, default headers on, CSP, no default creds | `a02_*` tests, Semgrep `cra-a02-*`, ZAP baseline |
| **A03** Software Supply Chain Failures | Part I (2)(a) no known exploitable vulnerabilities | Part II (1) SBOM, (2) remediate without delay | BOM-managed versions, Dependabot, SafeConstructor, input allowlist | CycloneDX SBOM + Trivy (nightly), Semgrep, `a03_*` test |
| **A04** Cryptographic Failures | Part I (2)(e) confidentiality, "state of the art" | (2)(f) integrity | bcrypt via DelegatingPasswordEncoder, SecureRandom, AES-256-GCM with AAD, keys from env | FindSecBugs, Semgrep `cra-a04-*`, gitleaks, `a04_*` test |
| **A05** Injection | Part I (2)(a) | (2)(e),(f) | Bind parameters, domain primitive `SearchTerm`, LIKE escaping | FindSecBugs `SQL_INJECTION_*`, Semgrep, `a05_*` test |
| **A06** Insecure Design | Part I (1) appropriate level based on risk; Art. 13(2) risk assessment | (2)(d),(h) | Invariants in the model (`Setpoint`), 40-bit pairing code, attempt limiter | `a06_*` tests, threat model in `risk-assessment.md` |
| **A07** Authentication Failures | Part I (2)(d) authentication mechanisms | (2)(b) no default passwords | No factory account, start-up password policy, lockout via auth events | `a07_*` tests, `NoDefaultCredentialsTest` |
| **A08** Software or Data Integrity Failures | Part I (2)(f) integrity of programs | (2)(c) security updates; Part II (7) secure distribution | Ed25519-signed firmware manifest, anti-rollback, SLSA provenance + SBOM attestation | `a08_*` test, `FirmwareVerifierTest`, release workflow |
| **A09** Security Logging & Alerting Failures | Part I (2)(l) record and monitor relevant activity | (2)(d) report unauthorised access; Art. 14 reporting | ECS JSON logs, `SecurityAuditLog`, Micrometer counter for alerting | `a09_*` tests, Semgrep `cra-a09-*` |
| **A10** Mishandling of Exceptional Conditions | Part I (2)(k) reduce impact of incidents | (2)(d),(h),(j) | Parse once, typed commands, default-deny policy, RFC 9457 errors with incident id | `a10_*` tests, Semgrep `cra-a10-*` |

## What the Top 10 does not give you

| CRA obligation | Where it lives in this repo |
|---|---|
| Part I (2)(c) security updates, automatic where applicable | firmware verifier + release workflow (partial) |
| Part I (2)(g) data minimisation, (2)(i) impact on other networks, (2)(m) secure deletion | not covered – product decisions |
| Part II (4) public advisories, (5) CVD policy, (6) contact, (8) free updates | `SECURITY.md`, `security.txt` (with CSAF field) |
| Art. 13(2) risk assessment | `docs/cra/risk-assessment.md` |
| Art. 13(8) support period of at least 5 years | `SECURITY.md` supported versions |
| Art. 14 reporting (24 h / 72 h / 14 days) via ENISA Single Reporting Platform | `docs/cra/vulnerability-handling.md` |
| Annex VII technical documentation, conformity assessment, CE marking | `docs/cra/technical-documentation.md` (outline) |
