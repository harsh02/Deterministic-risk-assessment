# DetRisk Risk Engine - AI Coding Agent Instructions

## 🎯 Project Overview

**DetRisk** is an AI-powered cybersecurity risk assessment engine that scores threats using multi-source intelligence (NVD CVE, CISA KEV, MITRE ATT&CK, EPSS) and semantic NLP. It provides instant risk scoring (Likelihood + Severity → 5x5 Risk Matrix) for both CVE IDs and plain-text threat descriptions.

**Core Problem**: Organizations receive hundreds of CVEs/threats daily. Manual triage is slow, CVSS alone is insufficient (a CVSS 9.8 with no exploits < CVSS 7.2 with active exploitation). Context matters: internet-facing vs internal, critical systems, safety implications.

**Core Solution**: Multi-source intelligence + AI semantic understanding + context-aware scoring + industry-specific packs.

---

## 🏗️ Architecture

### High-Level Flow
```
Input (CVE ID or description) 
  → Feature Extraction (Resolver Pattern)
    → Database Lookups (NVD, KEV, ATT&CK, EPSS)
    → Semantic Search Fallback (if no exact match)
    → NLP Extraction (spaCy for impact/scope)
  → Scoring Engine
    → Likelihood Formula (exploitability + KEV + frequency + EPSS)
    → Severity Formula (CVSS + context + impact)
    → 5x5 Risk Matrix → Overall Risk (Critical/High/Medium/Low)
  → Output (Risk scores + Evidence trail)
```

### Key Components

**1. Risk Engine (`src/utils/risk_engine.py`, 1591 lines)**
- **Core Functions**:
  - `load_config()` - Load YAML policy files
  - `deterministic_features_from_dbs()` (line 1419) - Orchestrates all resolvers
  - `compute_scores()` (line 1506+) - Calculate likelihood/severity from formulas
  - `build_features()` (line 1459+) - Merge defaults + DB features + manual overrides
  
- **Resolver Pattern** (each returns `(features_dict, evidence_dict)`):
  - `resolve_from_cve()` (lines 341-507) - NVD CVE lookup, CVSS scores, semantic fallback
  - `resolve_from_kev()` - CISA KEV database (known exploited vulnerabilities)
  - `resolve_attack_frequency()` (lines 549-651) - MITRE ATT&CK with semantic fallback
  - `resolve_from_epss()` (lines 752-838) - EPSS exploit prediction scores
  - `resolve_emb3d_maturity()` - EMB3D embedded device security
  - `resolve_internal_safety()` - Safety keyword extraction
  - `extract_impact_category()`, `extract_data_sensitivity()`, `extract_impact_scope()` - NLP extractors

- **Safe Formula Evaluator** (lines 60-180):
  - `SafeFormulaEvaluator` class - AST-based parser to prevent code injection
  - Supports: `+`, `-`, `*`, `/`, `min()`, `max()`, `abs()`, `round()`, `clamp()`, `norm()`
  - Used for YAML formula evaluation (likelihood/severity)

**2. Semantic Search (`src/utils/semantic_search.py`, 228 lines)**
- **Model**: `sentence-transformers/all-MiniLM-L6-v2` (384-dim embeddings)
- **Functions**:
  - `load_model()` - Cached model loading
  - `search_cves()` - Find CVEs from vague descriptions
  - `search_mitre_ttps()` - Find MITRE techniques from attack descriptions
  - `load_cve_index()`, `load_mitre_index()` - Load pre-built embeddings

- **Indexes** (`indexes/` directory):
  - `cve_embeddings.npy` + `cve_metadata.json` (3,637 CVEs embedded)
  - `mitre_embeddings.npy` + `mitre_metadata.json` (679 techniques embedded)
  - Built by `src/utils/build_indexes.py` (~10 seconds to rebuild)

**3. Index Builder (`src/utils/build_indexes.py`, 286 lines)**
- `build_cve_index()` - Embed CVE descriptions from NVD database
- `build_mitre_index()` - Embed MITRE technique descriptions
- Run once to build indexes: `python src/utils/build_indexes.py`

**4. Interactive CLI (`src/utils/risk_chat.py`, 398 lines)**
- Chat interface: `python src/utils/risk_chat.py --config <yaml>`
- JSON mode: `echo '{"cve": "CVE-2024-21413"}' | python src/utils/risk_chat.py`
- Displays: Risk scores, evidence chain, semantic matches, database sources

---

## 📦 Industry Configuration Packs

**Location**: `policy/industry-packs/`
**Structure**: YAML files defining scoring formulas, features, databases, asset types

### Available Packs

**1. General IT (`general-it.yaml`)**
- Target: Enterprise IT, cloud, web apps
- Likelihood: `35% CVSS + 35% KEV + 20% Attack Frequency + 10% EPSS`
- Severity: `70% CVSS Base + 20% Context Criticality + 10% Scope`
- Use case: Most organizations, balanced scoring

**2. ICS/OT/Embedded (`ics-ot-embedded.yaml`)**
- Target: SCADA, PLCs, IoT, industrial control systems
- Likelihood: `25% CVSS + 30% KEV + 15% Freq + 10% EPSS + 10% Device Maturity + 10% Legacy Systems`
- Severity: `40% Safety Impact + 25% Availability + 15% Physical Process + 10% CVSS + 10% Scope`
- Priority: **Safety > Availability > Integrity > Confidentiality**
- Additional features: `Safety_Impact`, `Physical_Process_Impact`, `Device_Maturity`, `Network_Segmentation`

**3. Medical Devices (`medical-devices.yaml`)**
- Target: FDA-regulated medical devices, hospital IT, IoMT
- Likelihood: Similar to ICS/OT with `FDA_Recall_History` integration
- Severity: `50% Patient Safety + 20% PHI Exposure + 15% Clinical Workflow + 10% CVSS + 5% Scope`
- Priority: **Patient Safety > PHI Protection > Availability**
- Additional features: `Patient_Safety_Impact`, `PHI_Exposure_Risk`, `Clinical_Workflow_Disruption`, `FDA_Recall_History`

**Usage**:
```bash
python src/utils/run_risk.py --config policy/industry-packs/ics-ot-embedded.yaml
python src/utils/risk_chat.py --config policy/industry-packs/medical-devices.yaml
```

**Full Documentation**: `policy/industry-packs/README.md` (442 lines)

---

## 🗄️ Databases

**Public Sources** (shared across all packs):
- **NVD CVE** (3,637 entries) - `data/nvdcve-2.0-modified.json` - CVSS scores, descriptions
- **CISA KEV** (1,447 entries) - `data/known_exploited_vulnerabilities.json` - Known exploited CVEs
- **MITRE ATT&CK** (679 techniques) - `data/enterprise-attack.json` - Attack patterns
- **EPSS** (296,428 entries) - `data/epss_scores-2025-01-05.csv.gz` - Exploit prediction scores

**Industry-Specific** (ICS/OT pack):
- MITRE ATT&CK for ICS
- ICS-CERT advisories
- EMB3D (embedded device security)

**Industry-Specific** (Medical pack):
- FDA MAUDE (adverse event reports)
- FDA device recalls database
- HHS breach portal

**Database Updates**:
```bash
python src/utils/setup_databases.py  # Download/update all databases
python src/utils/build_indexes.py    # Rebuild semantic indexes after updates
```

---

## 🧪 Testing

**Test Structure**:
- `tests/unit/` - Unit tests for components
- `tests/integration/` - End-to-end scenarios

**Key Test Files**:
- `tests/unit/test_threat.py` - Core risk assessment
- `tests/unit/test_spacy_nlp.py` - NLP extraction
- `tests/unit/test_enhanced_extraction.py` - Feature extraction

**Run Tests**:
```bash
pytest tests/                           # All tests
pytest tests/unit/test_threat.py       # Specific test file
pytest -v                               # Verbose mode
```

**Preflight Check**:
```bash
python src/utils/preflight_check.py    # Verify config, databases, dependencies
```

---

## 🔧 Development Workflows

### Adding a New Feature
1. Define in YAML config (`features` section):
   ```yaml
   features:
     - name: New_Feature_Name
       default: 0.5
       description: "What this measures"
   ```

2. Create resolver function in `risk_engine.py`:
   ```python
   def resolve_new_feature(cfg, input_payload) -> tuple[Dict[str, float], Dict[str, Any]]:
       # Extract feature value from input/database
       features = {"New_Feature_Name": value}
       evidence = {"source": "...", "features": features}
       return features, evidence
   ```

3. Add to `deterministic_features_from_dbs()` resolver list (line 1419)

4. Update scoring formula in YAML:
   ```yaml
   scoring:
     likelihood:
       formula: "0.35 * Exploitability + 0.10 * New_Feature_Name"
   ```

### Creating a New Industry Pack
1. Copy `policy/industry-packs/general-it.yaml`
2. Modify `meta.industry` field
3. Adjust scoring formulas (likelihood/severity)
4. Add industry-specific features
5. Define asset types and criticality levels
6. Document in `policy/industry-packs/README.md`
7. Test: `python src/utils/run_risk.py --config policy/industry-packs/your-pack.yaml`

### Adding a New Database Source
1. Download/prepare data file (JSON/CSV format)
2. Add path to `sources.file_paths` in YAML config
3. Create resolver function (return `(features, evidence)`)
4. Add to `deterministic_features_from_dbs()` resolver list
5. If searchable, add to `build_indexes.py` for semantic indexing

### Debugging Risk Scores
1. Run with verbose evidence: `python src/utils/risk_chat.py --verbose`
2. Check evidence chain - shows which databases contributed
3. Verify feature values in output: `"feature_breakdown": {...}`
4. Check formula evaluation in `compute_scores()` (line 1506+)
5. Use preflight check: `python src/utils/preflight_check.py`

---

## 📝 Project Conventions

### Code Style
- **Python 3.11+** required
- Type hints: `def func() -> tuple[Dict[str, float], Dict[str, Any]]`
- Docstrings: Google style
- Logging: Use `logger.info()` / `logger.warning()` (not `print()`)
- Error handling: Resolvers return empty `({}, {})` on failure (don't crash)

### YAML Config Structure
```yaml
meta:
  version: "2.0"
  industry: "General IT"

sources:
  file_paths:
    cve: "data/nvdcve-2.0-modified.json"
    kev: "data/known_exploited_vulnerabilities.json"
    # ... more databases

features:
  - name: Feature_Name
    default: 0.5
    description: "What this measures"

scoring:
  likelihood:
    formula: "0.35 * Exploitability + 0.35 * KnownExploited + 0.20 * AttackFrequency + 0.10 * EPSS_Score"
    clamp: [0, 1]
  
  severity:
    with_cvss_formula: "0.70 * norm(CVSS_BaseScore, 0, 10) + 0.20 * context_criticality + 0.10 * norm(Impact_Scope, 0, 1)"
    without_cvss_formula: "0.40 * norm(ImpactCategory, 0, 4) + 0.30 * DataSensitivity + 0.20 * context_criticality + 0.10 * norm(Impact_Scope, 0, 1)"
    clamp: [0, 10]
  
  overall_risk:
    matrix:
      bins: [0.2, 0.4, 0.6, 0.8]
      table:  # 5x5 matrix (likelihood x severity)
        - ["Low", "Low", "Medium", "Medium", "High"]
        # ... more rows
```

### Evidence Chain Structure
Every resolver returns:
```python
features = {
    "Feature_Name": float_value,
    # ... more features
}

evidence = {
    "source": "Database Name",
    "cve_id": "CVE-2024-XXXXX",  # Optional
    "confidence": 0.8,  # Optional
    "features": features,
    "match_type": "exact" | "semantic",  # If semantic search used
    "similarity": 0.92,  # If semantic search
    # ... more context
}

return features, evidence
```

### File Paths
- Always use absolute paths or resolve relative to config file
- Config-relative path resolution: `_get_config_base_dir(cfg)` (line 260+)
- Database files: `data/` directory
- Semantic indexes: `indexes/` directory
- Config files: `policy/` or `policy/industry-packs/`

---

## 🔌 Internal Data Integration

**Hook Pattern**: Resolvers can integrate internal data sources (SAST, pentest, incidents)

**Example Internal Hooks** (documented in main README):
- **SAST/DAST**: SonarQube, Veracode scan results
  - "This CWE appeared 15 times in last 6 months" → Higher likelihood
- **Pentest Results**: Exploitability validation
  - "Successfully exploited in last pentest" → Likelihood = 1.0
- **Incident History**: Attack tracking
  - "Similar attack occurred 3 times last year" → Higher frequency
- **Asset Inventory**: Exposure context
  - "Public-facing web server with 10M users" → Higher criticality

**Implementation**: Create custom resolver, add to config YAML, integrate in `deterministic_features_from_dbs()`

---

## 🚀 Quick Reference Commands

```bash
# Setup
python src/utils/setup_databases.py        # Download databases
python src/utils/build_indexes.py          # Build semantic indexes
python src/utils/preflight_check.py        # Verify setup

# Risk Assessment
python src/utils/run_risk.py --config policy/industry-packs/general-it.yaml
python src/utils/risk_chat.py --config policy/industry-packs/ics-ot-embedded.yaml

# JSON Input
echo '{"cve": "CVE-2024-21413", "asset_type": "SCADA_Server"}' | python src/utils/risk_chat.py --config policy/industry-packs/ics-ot-embedded.yaml

# Testing
pytest tests/
python tests/unit/test_threat.py
```

---

## 🎓 Key Concepts

**Likelihood (0-1)**: Probability of exploitation
- Combines: CVSS exploitability, KEV status, attack frequency, EPSS score
- Formula varies by industry pack (general-it vs ics-ot vs medical)

**Severity (0-10)**: Impact magnitude
- Combines: CVSS base score, context criticality, data sensitivity, scope
- Dual-mode: `with_cvss_formula` (when CVE exists) vs `without_cvss_formula` (plain text)

**5x5 Risk Matrix**: Maps (likelihood, severity) → Overall Risk
- Bins: [0.2, 0.4, 0.6, 0.8] divide range into 5 levels
- Output: Critical / High / Medium / Low

**Resolver Pattern**: Modular feature extraction
- Each resolver queries one data source (CVE, KEV, ATT&CK, etc.)
- Returns `(features_dict, evidence_dict)` or `({}, {})` on failure
- Evidence chain tracks data provenance for transparency

**Semantic Fallback**: When no exact CVE/TTP match
- Embeds input description with sentence-transformers
- Computes cosine similarity against pre-built index
- Returns top-k matches with similarity scores
- Used by `resolve_from_cve()` and `resolve_attack_frequency()`

**Industry Packs**: Sector-specific scoring priorities
- General IT: Balanced (confidentiality focus)
- ICS/OT: Safety-first (physical consequences)
- Medical: Patient safety paramount (FDA/HIPAA compliance)

---

## 📚 Additional Documentation

- **Main README**: `/README.md` (359 lines) - Installation, quick start, examples
- **Industry Packs**: `/policy/industry-packs/README.md` (442 lines) - Detailed pack comparison, examples
- **Project Structure**: `/PROJECT_STRUCTURE.md` - File organization
- **Generic Threats**: `/GENERIC_THREATS.md` - Cross-industry threat examples
- **Scoring Explained**: `/SCORING_EXPLAINED.md` - Formula derivation, rationale

---

## 🎯 AI Agent Guidelines

**When adding features**:
1. Always update YAML config first
2. Create resolver function with `(features, evidence)` return signature
3. Add to resolver list in `deterministic_features_from_dbs()`
4. Test with `pytest` and preflight check

**When debugging**:
1. Check evidence chain for data source verification
2. Verify formula syntax (use `SafeFormulaEvaluator` allowed operators)
3. Check feature defaults in YAML config
4. Run preflight check for database/config issues

**When creating industry packs**:
1. Identify sector-specific priorities (e.g., safety > availability for ICS)
2. Adjust scoring formula weights accordingly
3. Add industry-specific features and databases
4. Define asset types and criticality levels
5. Document use cases and examples
6. Test with realistic scenarios

**Best practices**:
- Always use type hints and docstrings
- Resolvers should gracefully handle missing data (return `({}, {})`)
- Log important operations (`logger.info()`)
- Never use `eval()` - use `SafeFormulaEvaluator` for formula parsing
- Update indexes after database changes (`build_indexes.py`)
- Test with multiple industry packs to ensure compatibility

---

## 🔒 Security Considerations

- **Formula Evaluation**: Uses AST-based parser (`SafeFormulaEvaluator`) to prevent code injection
- **Input Validation**: Sanitize user input before processing
- **Database Integrity**: Verify checksums after downloads
- **Dependency Management**: Pin versions in `requirements.txt`

---

**Version**: 2.0  
**Last Updated**: January 2025  
**Maintainer**: DetRisk Development Team
