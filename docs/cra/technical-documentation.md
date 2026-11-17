# Technical documentation outline (Annex VII) – where the evidence comes from

| Annex VII item | Content | Generated / maintained by |
|---|---|---|
| 1 General description | intended purpose, versions affecting compliance, user information (Annex II) | product docs |
| 2(a) Design and development | architecture, how components build on each other | architecture docs |
| 2(b) Vulnerability handling processes | SBOM, CVD policy, contact, secure update distribution | `docs/cra/vulnerability-handling.md`, `SECURITY.md`, `target/bom.json`, `release.yml` |
| 2(c) Production and monitoring processes | build pipeline, gates, release validation | `.github/workflows/*.yml` |
| 3 Cybersecurity risk assessment (Art. 13(2)) | threats, applicability of Annex I Part I (2) | `docs/cra/risk-assessment.md` |
| 4 Support period rationale (Art. 13(8)) | expected use time, user expectations | `SECURITY.md` |
| 5 Harmonised standards / specifications applied | EN 40000 series once cited; until then the state of the art used | this file |
| 6 Test reports for conformity with Annex I | conformance suite reports, SAST/SCA results | `target/cra-conformance-report-*.md`, `spotbugsSarif.json`, CI artefacts |
| 7 EU declaration of conformity | Annex V | release process |
| 8 SBOM (on request of market surveillance) | CycloneDX JSON/XML per release | `-Pcra-sbom`, release assets |

Keep it for **10 years** after placing on the market, or until the end of the support period if later.
