# DetRisk — Deterministic Risk Assessment Engine

In most Product Security organizations, risk prioritization is inconsistent. Different architects score the same threat differently. Distributed teams across dozens of services apply ad-hoc judgment, CVSS alone, or spreadsheet-based triage — producing ratings that cannot be compared, reproduced, or defended under audit. This inconsistency compounds at scale: when 200+ threats across 10+ services are scored by different people using different criteria, remediation focus drifts from actual risk toward whoever argued most convincingly in the last meeting.

DetRisk is a deterministic risk assessment engine that eliminates this drift. It ingests structured threat data, enriches it against public intelligence sources, separates likelihood from severity using configurable YAML-defined formulas, and produces auditable, fully reproducible risk scores with complete evidence provenance. Every assessment is a deterministic function of its inputs — verifiable, traceable, and identical regardless of who runs it or when.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)]()
[![License: MIT](https://img.shields.io/badge/license-MIT-green)]()
[![Tests](https://img.shields.io/badge/tests-18%20passing-brightgreen)]()

---

## Problem Statement

Product Security teams face a structural problem in risk prioritization: the tools and processes used to assess threats do not produce consistent, defensible, or traceable results.

**CVSS alone is insufficient for operational risk decisions.** A CVSS 9.8 vulnerability behind a compensating control with no public exploit may present less operational risk than a CVSS 7.2 with active exploitation, a CISA KEV listing, and an EPSS score above 0.90. CVSS measures intrinsic severity — it does not account for exploitation likelihood, deployment context, or organizational risk appetite.

**Most scoring processes are non-reproducible.** When risk ratings depend on analyst judgment, spreadsheet formulas, or opaque ML models, two analysts assessing the same threat will produce different scores. This creates audit gaps, undermines regulatory reporting, and makes quarter-over-quarter risk posture tracking unreliable.

**Likelihood and impact are routinely conflated.** Collapsing "how likely is exploitation?" and "how severe is the outcome?" into a single number prevents teams from answering the questions that drive resource allocation: Which threats are probable but manageable? Which are unlikely but catastrophic? Which axis improved this quarter?

**Unstructured threats are excluded from scoring.** Not every risk arrives as a CVE. Pen-test findings, threat-intel briefs, and incident post-mortems are free-text — they require the same scoring rigor as a catalogued vulnerability, but most tooling has no entry point for them.

DetRisk addresses these gaps with a deterministic, formula-driven engine whose outputs are fully reproducible given the same inputs and configuration.

---

## Scaled Organizational Scenario

Consider a Product Security team responsible for 12 services across three business units. Each quarter, threat modeling sessions produce 200+ identified threats. Under a subjective scoring process, three different architects rate the same "unauthenticated API endpoint exposing PII" as High, Critical, and Medium respectively — based on their individual judgment, familiarity with compensating controls, and interpretation of severity.

The consequence: remediation backlogs across services are not comparable. A "Critical" in Service A may represent less operational risk than a "High" in Service B. Leadership cannot allocate resources across business units because the ratings do not share a common basis. Quarterly governance reports show risk reduction, but the numbers are not reproducible and would not survive an audit challenge.

With DetRisk, the same threat description processed against the same intelligence data and policy configuration produces the same score — regardless of which architect submits it. Backlogs become comparable across services. Governance reports are backed by reproducible evidence. Resource allocation decisions are grounded in consistent data rather than individual interpretation.

---

## Solution Overview

DetRisk accepts structured or semi-structured threat input — JSON payloads containing optional CVE IDs, MITRE ATT&CK technique references, and free-text descriptions — resolves each input against public intelligence databases, and computes separated **likelihood** and **severity** scores using configurable formulas declared in YAML.

**Deterministic.** The same input, configuration, and data snapshot always produces the same output. No stochastic components influence the final score.

**Separated likelihood and severity.** Likelihood measures exploitation probability (CVSS exploitability, KEV status, EPSS, attack frequency, temporal context). Severity measures outcome magnitude (CVSS base score, impact category, data sensitivity, asset criticality). These are composed into a 5×5 risk matrix only at the final classification step.

**Evidence-traced.** Every feature value is tagged with its provenance — which resolver produced it, from which data source, with what confidence. The full evidence chain is returned alongside scores.

**Configuration-driven.** Scoring formulas, feature weights, and data source paths are declared in `policy/risk_rules.hybrid.yaml`. Changing risk policy does not require code changes.

---

## What This Is Not

**Not a CVSS replacement.** DetRisk consumes CVSS as one input among several. It does not redefine CVSS scoring methodology or claim to supersede it. CVSS measures intrinsic vulnerability severity; DetRisk contextualizes that severity within a broader operational risk model that includes exploitation likelihood, temporal signals, and organizational context.

**Not an AI auto-triage engine.** There is no machine learning model making classification decisions. Scoring is formula-driven, deterministic, and fully transparent. The NLP component extracts structured features from free text — it does not predict or classify risk autonomously.

**Not a compliance tool.** DetRisk does not implement or enforce any specific regulatory framework. It produces structured, evidence-traced risk assessments that can feed into compliance workflows, but mapping scores to specific regulatory requirements (PCI-DSS, SOC 2, HIPAA) is an organizational responsibility, not an engine function.

**Not a vulnerability scanner.** DetRisk does not discover vulnerabilities. It scores threats that have already been identified — whether from scanners, threat models, pen-test reports, or incident post-mortems.

---

## Architecture

```
         ┌───────────────────┐
         │  Input (JSON)     │
         │  CVE / TTP / text │
         └────────┬──────────┘
                  │
         ┌────────▼──────────┐
         │  Enrich           │
         │  NVD · KEV · EPSS │
         │  MITRE · NLP      │
         └────────┬──────────┘
                  │
        ┌─────────┼─────────┐
        │                   │
  ┌─────▼─────┐      ┌──────▼─────┐
  │ Likelihood│      │  Severity  │
  │ exploit.  │      │  CVSS base │
  │ KEV, EPSS │      │  impact    │
  │ freq,temp │      │  sens,crit │
  └─────┬─────┘      └──────┬─────┘
        │                   │
        └─────────┬─────────┘
                  │
         ┌────────▼──────────┐
         │  Classify         │
         │  YAML formulas    │
         │  5×5 risk matrix  │
         └────────┬──────────┘
                  │
         ┌────────▼──────────┐
         │  Output (JSON)    │
         │  scores + evidence│
         └───────────────────┘
```

Four stages: **Enrich** resolves inputs against NVD, KEV, EPSS, and MITRE ATT&CK with NLP extraction for unstructured text. **Assemble** produces a normalized feature vector with tagged provenance. **Score** evaluates YAML formulas via a safe AST-based evaluator (no `eval()`). **Classify** maps likelihood and severity to a 5×5 risk matrix.

All stages are stateless. Enrichment uses indexed caches for O(1) lookups against local data snapshots. NLP supports spaCy and keyword-only fallback.

---

## Design Decisions

### Deterministic scoring over ML

ML-based risk models introduce opacity. They resist explanation at the individual-prediction level, require retraining when threat landscapes shift, and produce outputs that cannot be independently verified by auditors or security leadership. DetRisk uses explicit, weighted formulas defined in YAML. Every score is a deterministic function of its inputs — verifiable, reproducible, and auditable without access to model internals.

### Separated likelihood and severity

ISO 27005, NIST SP 800-30, and FAIR all define risk as a function of two independent axes. Collapsing them into a single number — as CVSS effectively does — prevents teams from isolating which axis drives a rating and tracking each independently over time. DetRisk maintains this separation through the entire pipeline and composes them only at the final classification step.

### Configuration as policy

Scoring formulas, feature weights, thresholds, and data source paths live in `policy/risk_rules.hybrid.yaml`. This means:

- Adjusting risk appetite (e.g., weighting KEV status at 25% vs 35%) is a YAML edit, not a code change.
- Policy changes are version-controlled and auditable in the same repository as the engine.
- Different business units or product lines can maintain separate policy files without forking the engine.

### Structured JSON schemas

Input and output are both structured JSON. This eliminates ambiguity in what was assessed and what was produced, enables programmatic consumption by downstream systems (GRC platforms, CI pipelines, dashboards), and creates an audit trail where each assessment is a self-contained, reproducible record.

### Dual-mode severity

When a CVE is present the engine uses the `with_cvss` formula anchored on CVSS base score. When the input is free-text without a CVE, severity switches to the `without_cvss` formula anchored on NLP-extracted impact category and data sensitivity. This avoids defaulting to zero for unstructured threats while preserving CVSS fidelity when available.

---

## Risk Modeling Philosophy

### Why reproducibility matters

Subjective triage creates systemic drift. When risk ratings depend on individual judgment, the same threat assessed by different analysts — or by the same analyst on different days — produces different scores. Over time, this drift compounds: risk registers become internally inconsistent, quarter-over-quarter trends are unreliable, and governance reports cannot withstand scrutiny. The problem is not that analysts lack expertise; it is that subjective processes are structurally incapable of producing consistent outputs at organizational scale.

DetRisk eliminates this class of problem entirely. Identical inputs, configuration, and data snapshots produce identical outputs — always. This is not a convenience property. It is the minimum viable requirement for any risk methodology that feeds into audit trails, regulatory filings, or executive-level resource allocation decisions.

### Why separate likelihood from impact

A single composite score cannot answer the operational questions that drive security investment:

- **"Which threats are probable but manageable?"** → Candidates for automated remediation or risk acceptance.
- **"Which threats are unlikely but catastrophic?"** → Candidates for compensating controls, monitoring, and incident planning.
- **"Has our exploitation-likelihood posture improved this quarter?"** → A measurable, trackable governance metric that a composite score obscures.

DetRisk keeps these axes independent and only combines them at the final step via a configurable 5×5 risk matrix. This enables both tactical triage and strategic governance reporting from the same underlying data — without forcing a premature collapse into a single number.

### Why evidence provenance

Every feature value in the output is tagged with the resolver that produced it, the data source it came from, and (where applicable) the confidence or similarity score. This is not optional metadata — it is the mechanism by which any risk rating can be challenged, investigated, and explained from executive summary down to source data point. When a CISO asks "why is this Critical?", the answer is in the JSON, not in someone's recollection of the triage meeting.

---

## How This Applies to Product Security Teams

### Threat modeling at scale

Manual threat modeling produces valuable findings but does not scale when applied across dozens of products and hundreds of identified threats per quarter. DetRisk provides a consistent scoring function that can be applied programmatically to threat model outputs, ensuring that threats identified across different products, teams, and architects are assessed against the same criteria and produce comparable risk ratings.

### SDLC integration

DetRisk operates on structured JSON input and produces structured JSON output. This makes it suitable for integration at multiple points in the development lifecycle:

- **Design review:** Score threats identified during threat modeling sessions using `run_risk_cli.py` to produce immediate, evidence-backed risk ratings.
- **CI/CD gates:** Run batch assessments via `run_risk.py` in pipeline steps. Concrete example: a GitHub Actions step runs `run_risk.py` against the threat inventory for a service. If any assessment returns `overall_risk: Critical` and no approved exception exists in `policy/overrides.yaml`, the pipeline fails and blocks deployment. This enforces risk-aware release gates without manual intervention.
- **Vulnerability management:** Process scanner output (SAST, DAST, SCA) through the engine to produce prioritized remediation queues ranked by operational risk rather than raw CVSS.

### Backlog prioritization

Security teams frequently struggle to justify why one vulnerability should be remediated before another. DetRisk produces separated likelihood and severity scores with full evidence chains. This transforms backlog prioritization from opinion-based ("I think this is more important") to evidence-based ("This has active exploitation, a KEV listing, and an EPSS score of 0.94 — here is the JSON").

### Governance and compliance reporting

Because every assessment is deterministic, evidence-traced, and emitted as structured JSON, DetRisk output feeds directly into risk registers, GRC platforms, and regulatory reports. Quarter-over-quarter posture changes are measurable: re-run the same threat inventory against updated intelligence data and compare the outputs programmatically.

---

## Example Walkthrough

### Input

```json
{
  "title": "SQL injection in payment processing gateway",
  "description": "Unauthenticated SQL injection in the payment API endpoint allows extraction of credit card data. Actively exploited in the wild.",
  "cve": "CVE-2024-21413"
}
```

### Enrichment

1. **NVD resolver** looks up CVE-2024-21413 → extracts `CVSS_BaseScore: 9.8`, `CVSS_Exploitability: 3.9`.
2. **KEV resolver** checks CISA catalog → `KnownExploited: 1.0`.
3. **EPSS resolver** retrieves exploit prediction → `EPSS_Score: 0.94`.
4. **MITRE semantic search** matches T1190 (Exploit Public-Facing Application) → `Attack_Frequency: 0.85`.
5. **NLP extractors** parse description → `Impact_Category: 0.9` (SQL injection), `Data_Sensitivity: 1.0` (credit card), `Attack_Vector_Exploitability: 0.9` (unauthenticated SQLi).
6. **Temporal context** → active threat, `Temporal_Likelihood_Modifier: 1.0`.

### Scoring (using default formula weights)

```
Likelihood = 1.0 * (0.25 * norm(3.9, 0, 10)
                   + 0.25 * 1.0
                   + 0.15 * 0.85
                   + 0.10 * 0.94
                   + 0.25 * 0.9)
           = 1.0 * (0.0975 + 0.25 + 0.1275 + 0.094 + 0.225)
           = 0.794

Severity   = 0.70 * norm(9.8, 0, 10) + 0.20 * 0.5 + 0.10 * 0.5
           = 0.686 + 0.10 + 0.05
           = 0.836

Overall    = matrix_lookup(0.794, 0.836) → Critical
```

### Output

```json
{
  "likelihood": 0.794,
  "severity": 0.836,
  "overall_risk": "Critical",
  "severity_mode": "with_cvss",
  "evidence": [
    {"source": "NVD CVE Database", "cve_id": "CVE-2024-21413", "cvss_version": "3.1"},
    {"source": "CISA KEV Database", "exploit_status": "ACTIVELY EXPLOITED"},
    {"source": "EPSS Database", "epss_score": 0.94, "percentile": 0.99},
    {"source": "MITRE ATT&CK (Semantic)", "technique_id": "T1190", "similarity": 0.87},
    {"source": "Attack Vector Analysis (NLP)", "matched_vector": "sql injection"},
    {"source": "Data Sensitivity Extraction", "sensitivity_level": "Critical"}
  ]
}
```

Every field in the output traces back to a named resolver and data source. No score is unexplained.

---

## Usage

### Prerequisites

```bash
pip install -r requirements.txt

# Optional: improved NLP extraction accuracy (~85% vs ~70% keyword-only)
python -m spacy download en_core_web_md

# Optional: refresh public intelligence feeds
python scripts/sync_intel_feeds.py --only kev
```

### CLI — Single Assessment

```bash
cd src/utils

python run_risk_cli.py \
  --title "Remote code execution in Outlook" \
  --description "CVE-2024-21413 allows remote code execution via crafted email links." \
  --cve CVE-2024-21413
```

### CLI — Batch Processing

```bash
python run_risk.py \
  --config ../../policy/risk_rules.hybrid.yaml \
  --input threat_payload.json \
  --output results.json
```

### Python API

```python
from risk_engine import load_config, build_features, compute_scores

cfg = load_config("policy/risk_rules.hybrid.yaml")

payload = {
    "title": "Ransomware encrypted production servers",
    "description": "Operations down for 3 days. Active incident response underway."
}

features, metadata = build_features(cfg, overrides={}, input_payload=payload)
scores = compute_scores(cfg, features, context={})

print(f"Likelihood: {scores['likelihood']:.3f}")
print(f"Severity:   {scores['severity']:.3f}")
print(f"Risk:       {scores['overall_risk']}")
```

### Interactive Chat Mode

```bash
cd src/utils
python risk_chat.py
```

Accepts natural language threat descriptions, CVE IDs, and optional manual overrides in a REPL interface.

### Preflight Verification

```bash
cd src/utils
python preflight_check.py
```

Validates Python version, dependencies, configuration, and data file availability before first use.

---

## Extensibility

The engine accepts pluggable data sources for organizational context — SAST/DAST scan results, pen-test reports, incident response history, compliance metadata. Internal hooks are disabled by default with conservative fallback values; enable them in YAML and adjust formula weights to calibrate against real-world data.

For configuration-driven policy changes, CI/CD integration, and SDLC integration points, see the [Design Decisions](#design-decisions) and [How This Applies to Product Security Teams](#how-this-applies-to-product-security-teams) sections above.

---

## Repository Structure

```
detrisk/
├── src/utils/
│   ├── risk_engine.py              # Core: feature assembly, formula evaluation, scoring
│   ├── run_risk_cli.py             # CLI: single-payload assessment
│   ├── run_risk.py                 # CLI: batch processing with JSON I/O
│   ├── risk_chat.py                # Interactive REPL for natural language input
│   ├── semantic_search.py          # Embedding-based CVE/TTP similarity search
│   ├── build_indexes.py            # Builds vector indexes for semantic search
│   ├── feature_extractor.py        # TaxonomyExtractor: YAML-driven NLP pattern matching
│   ├── temporal_proxy.py           # Adapter for temporal risk plugin
│   ├── preflight_check.py          # Dependency and config validation
│   └── setup_databases.py          # Placeholder data file generator
├── policy/
│   ├── risk_rules.hybrid.yaml     # Scoring formulas, feature definitions, data paths
│   ├── taxonomy.yaml              # 292 externalized NLP patterns for extraction
│   ├── feeds.yaml                 # Declarative feed config for sync_intel_feeds.py
│   └── industry-packs/            # Modular risk policy overlays (ICS/OT, medical, general IT)
├── data/                           # Intelligence feeds (NVD, KEV, MITRE, EPSS, GHSA)
├── indexes/                        # Pre-built vector indexes for semantic search
├── scripts/
│   └── sync_intel_feeds.py        # Feed synchronization with integrity checks
├── tests/unit/                     # 18+ unit tests (test_engine.py + supplementary suites)
└── docs/                           # Supplemental documentation
```

---

## Data Sources

| Source | Purpose | Update Mechanism |
|--------|---------|-----------------|
| NVD (National Vulnerability Database) | CVSS base scores, exploitability metrics | `sync_intel_feeds.py --only nvd` |
| CISA KEV | Known active exploitation status | `sync_intel_feeds.py --only kev` |
| MITRE ATT&CK | Attack technique frequency and tactics | `sync_intel_feeds.py --only mitre` |
| EPSS | 30-day exploit probability prediction | `sync_intel_feeds.py --only epss` |
| GHSA (GitHub Security Advisories) | Vulnerability advisories from GitHub ecosystem | `sync_intel_feeds.py --only ghsa` |

---

## Testing

```bash
# Run core test suite (18 tests)
cd src/utils
.venv/bin/python -m pytest ../../tests/unit/test_engine.py -v

# Run all tests
.venv/bin/python -m pytest ../../tests/ -v
```

---

## Limitations & Assumptions

**Weighted-formula assumptions.** The default formula weights in `policy/risk_rules.hybrid.yaml` reflect general-purpose Product Security priorities. They assume that KEV status, EPSS, and CVSS exploitability are reasonable proxies for exploitation likelihood, and that CVSS base score and NLP-extracted impact categories are reasonable proxies for severity. These assumptions hold well for enterprise application security but may require calibration for specialized domains (embedded systems, ICS/OT, healthcare devices) where threat distributions differ.

**Weighting bias.** Any fixed weighting scheme embeds assumptions about relative feature importance. The default weights prioritize exploitation evidence (KEV, EPSS) and known severity (CVSS). Organizations with different risk profiles — for example, those prioritizing data sensitivity over exploitability — should adjust weights to reflect their actual risk appetite. The engine makes this adjustment explicit and auditable via YAML, but the responsibility for calibration lies with the adopting organization.

**Domain-specific calibration.** The NLP taxonomy (`policy/taxonomy.yaml`) and scoring formulas were developed against general enterprise threat language. Domain-specific terminology, non-English threat descriptions, and highly specialized technical contexts may require taxonomy extension and formula tuning before the engine produces well-calibrated results.

---

## Limitations & Future Evolution

**Data currency.** Risk scores are only as current as the local intelligence snapshots. If feeds are not refreshed regularly via `sync_intel_feeds.py`, scores will reflect stale exploitation data. The engine does not fetch live data at assessment time — this is a deliberate design choice to ensure reproducibility, but it requires operational discipline around feed synchronization.

**NLP extraction boundaries.** The NLP pipeline (spaCy + keyword fallback) extracts impact categories, data sensitivity, and attack vectors from free-text descriptions. Highly technical or domain-specific language may not match taxonomy patterns. The taxonomy is externalized in `policy/taxonomy.yaml` and can be extended without code changes, but extraction accuracy depends on pattern coverage.

**Single-threat granularity.** Each assessment scores one threat at a time. The engine does not model compound threats, attack chains, or cumulative risk across multiple vulnerabilities affecting the same system. Aggregation across assessments is a downstream concern.

**Scaling.** The engine is designed for batch processing of hundreds to low thousands of threats. It is not optimized for real-time scoring of high-volume vulnerability streams. For environments requiring sub-second response times at scale, the engine would need to be wrapped in a service layer with pre-loaded indexes and connection pooling.

**Intelligence source bias.** NVD, KEV, EPSS, and MITRE ATT&CK are public, US-centric sources. Threats that are not catalogued in these databases (e.g., zero-days, region-specific campaigns, OT-specific vulnerabilities with limited public disclosure) will receive lower enrichment coverage and potentially understated risk scores.

---

## License

MIT License — see [LICENSE](LICENSE).