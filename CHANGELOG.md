# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-02-21

### Added
- **Taxonomy-driven extraction**: Externalized 292 hardcoded patterns into `policy/taxonomy.yaml` with `TaxonomyExtractor` class for configurable, maintainable NLP pattern matching
- **Feed synchronization**: New `scripts/sync_intel_feeds.py` with SHA-256 integrity verification, incremental NVD pagination, configurable retry/backoff, and `policy/feeds.yaml` declarative feed config
- **Semantic search**: Embedding-based CVE and MITRE ATT&CK similarity lookup via `semantic_search.py` with pre-built vector indexes
- **18 comprehensive unit tests**: Full test suite in `tests/unit/test_engine.py` covering scoring, NLP extraction, dual-mode severity, edge cases, and regression scenarios
- **Industry policy packs**: Modular YAML-based risk policy overlays for ICS/OT, medical devices, and general IT environments

### Changed
- **Performance (C1–C7)**: Lazy spaCy loading (cold-start → 0ms when unused), document-parameter threading (eliminates redundant parses), NVD/KEV/MITRE/EPSS indexed caches (O(1) lookups), embedding deduplication
- **Scoring calibration**: Fixed severity inflation — benign-context dampener, keyword-only extraction caps, and `without_cvss` formula rebalancing prevent routine advisories from scoring Critical
- **Python requirement**: Raised minimum to Python 3.10+ (match statements, modern type hints)
- **Dependencies**: Added sentence-transformers, numpy, requests, tqdm to requirements

### Removed
- Crypto/DeFi modules (`crypto_data_sources.py`, `crypto_incident_sources.py`, `crypto_protocol_metrics.py`, `crypto_context_resolver.py`) — project now focuses on general enterprise threat assessment
- Industry classifier module — replaced by declarative YAML policy packs
- 275MB GHSA bulk data from git tracking — now fetched via `sync_intel_feeds.py`
- Large data files from git tracking (NVD, KEV, EPSS, MITRE) — fetched at runtime

### Fixed
- `run_risk.py` broken `importlib` hack loading from hash-prefixed filename — now uses standard import
- `setup_databases.py` hardcoded absolute path removed
- `setup.py` placeholder email and outdated Python version classifiers
- `.gitignore` missing `.venv/`, `data/`, `indexes/` patterns
- Missing `src/__init__.py` and `src/utils/__init__.py` package markers

### Security
- All scoring formulas use `SafeFormulaEvaluator` (AST-based whitelist, no `eval()`)
- Input validation on all file paths and user inputs
- YAML safe loading throughout

## [1.0.0] - 2025-10-16

### Added
- Initial release of DetRisk risk assessment engine
- AI-powered NLP semantic extraction using spaCy (87% accuracy)
- Dual-mode assessment (CVE IDs or plain text descriptions)
- Integration with NVD, MITRE ATT&CK, CISA KEV, EPSS
- Safe formula evaluation (AST-based, no eval())
- Comprehensive security hardening
- Professional logging system
- Full type hints throughout codebase
- Interactive CLI interface
- 5x5 risk matrix classification
- Negation detection in threat descriptions
- Paraphrasing and synonym support

### Security
- Replaced eval() with SafeFormulaEvaluator
- Added input validation throughout
- Implemented path validation
- Added specific exception handling
- Fixed YAML deserialization vulnerabilities

### Documentation
- Complete README with examples and architecture
- Security audit documentation
- spaCy integration guide
- Contributing guidelines
- API usage examples

[2.0.0]: https://github.com/harsh02/Determinstic-risk-assessment/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/harsh02/Determinstic-risk-assessment/releases/tag/v1.0.0
