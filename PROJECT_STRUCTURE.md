# Project Structure & Architecture Review

## Repository Layout

```
detrisk/
├── src/utils/
│   ├── risk_engine.py              # Core: resolvers, feature assembly, formula evaluation, scoring
│   ├── run_risk_cli.py             # CLI: single-payload assessment (recommended entry point)
│   ├── run_risk.py                 # CLI: batch processing with JSON file I/O
│   ├── risk_chat.py                # Interactive REPL for natural language input
│   ├── semantic_search.py          # Embedding-based CVE/TTP similarity search
│   ├── build_indexes.py            # One-time index builder for semantic search
│   ├── temporal_proxy.py           # Plugin adapter for temporal risk scoring
│   ├── preflight_check.py          # Dependency and config validator
│   ├── setup_databases.py          # Placeholder data file generator
│   └── detrisk_internal/            # Internal plugin interface (temporal scoring)
│
├── policy/
│   ├── risk_rules.hybrid.yaml      # Primary risk policy: formulas, features, data paths
│   ├── taxonomy.yaml               # 292 externalized NLP patterns for feature extraction
│   ├── feeds.yaml                  # Declarative feed config for sync_intel_feeds.py
│   └── industry-packs/             # Modular risk policy overlays (ICS/OT, medical, general IT)
│
├── data/                            # Intelligence feed data (NVD, KEV, MITRE, EPSS, GHSA)
├── indexes/                         # Pre-built vector indexes for semantic search
├── scripts/
│   └── sync_intel_feeds.py          # Feed synchronization with integrity verification
├── tests/                           # Unit and integration tests
│   └── unit/                        # 18 tests in test_engine.py + supplementary suites
├── docs/                            # Supplemental documentation
├── requirements.txt
├── setup.py
└── LICENSE
```

## Architecture Review Notes

### Separation of concerns

The codebase maintains a clear separation between:

1. **Policy definition** (`policy/risk_rules.hybrid.yaml`) — formulas, weights, thresholds, and data paths are declarative and version-controlled.
2. **Enrichment/resolution** (resolver functions in `risk_engine.py`) — each data source has an isolated resolver that returns `(features, evidence)` tuples.
3. **Scoring** (`compute_scores`) — pure function that evaluates YAML-defined formulas against the assembled feature vector.
4. **I/O** (`run_risk_cli.py`, `run_risk.py`, `risk_chat.py`) — thin wrappers around the core engine.

### Observations for future consideration

- **`risk_engine.py` is large (~1850 lines).** Consider extracting resolvers into a `resolvers/` sub-package (e.g., `resolvers/nvd.py`, `resolvers/kev.py`, `resolvers/mitre.py`) and NLP extractors into an `extractors/` sub-package. This would improve testability and make individual resolvers independently deployable.
- **Module location under `src/utils/`** is unconventional. A flatter layout like `src/detrisk/engine.py` would follow standard Python packaging conventions and simplify imports.

### What works well

- The `SafeFormulaEvaluator` is a sound security pattern — AST-based whitelist evaluation eliminates code injection risk from YAML-defined formulas.
- Evidence provenance is comprehensive: every feature carries its resolver source, enabling full audit trails.
- Dual-mode severity (with/without CVSS) is a practical design for handling both CVE-based and text-only threats.
- The benign-context dampener is a thoughtful feature that prevents lab/training scenarios from inflating risk scores.
- Taxonomy-driven NLP extraction (`policy/taxonomy.yaml`) externalizes 292 patterns from code, making pattern updates a YAML edit rather than a code change.
- Feed synchronization (`scripts/sync_intel_feeds.py`) with SHA-256 integrity verification and declarative config (`policy/feeds.yaml`) ensures reproducible data pipelines.
