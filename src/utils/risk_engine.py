"""Core deterministic risk assessment engine.

This module implements the central scoring pipeline for DetRisk. It resolves
threat inputs against multiple intelligence sources (NVD, CISA KEV, MITRE
ATT&CK, EPSS), extracts features via NLP and keyword analysis, and computes
separated likelihood and severity scores using YAML-defined formulas.

Key entry points:
    load_config   -- Load and validate a YAML risk policy file.
    build_features -- Assemble feature values from defaults, resolvers, and overrides.
    compute_scores -- Evaluate likelihood/severity formulas and classify overall risk.

Design assumptions:
    - Scoring is fully deterministic: same config + data + input = same output.
    - Formulas are evaluated via AST-based safe evaluation (no eval/exec).
    - All resolver outputs carry evidence metadata for audit provenance.
    - NLP (spaCy) is optional; the engine degrades gracefully to keyword matching.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import logging
import sys
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

# ---------- NLP imports with lazy loading ----------
try:
    import spacy

    _SPACY_AVAILABLE = True
except ImportError:
    _SPACY_AVAILABLE = False

_nlp = None  # populated lazily by _get_nlp()
NLP_AVAILABLE = False  # set True once the model is loaded


def _get_nlp():
    """Lazy-load the spaCy language model on first use."""
    global _nlp, NLP_AVAILABLE
    if _nlp is not None:
        return _nlp
    if not _SPACY_AVAILABLE:
        logger.info("spaCy not installed — using keyword fallback")
        return None
    for model_name in ("en_core_web_md", "en_core_web_sm"):
        try:
            _nlp = spacy.load(model_name)
            NLP_AVAILABLE = True
            logger.info("spaCy NLP enabled (%s)", model_name)
            return _nlp
        except OSError:
            continue
    logger.warning(
        "spaCy installed but no model found. Run: python -m spacy download en_core_web_md"
    )
    return None


# ---------- Taxonomy-driven feature extractor ----------
from feature_extractor import (
    TaxonomyExtractor,  # noqa: E402 -- imported here so the optional dependency is loaded only after the preceding setup
)

_TAXONOMY_PATH = Path(__file__).parent.parent.parent / "policy" / "taxonomy.yaml"
_taxonomy: TaxonomyExtractor | None = None


def _get_taxonomy() -> TaxonomyExtractor:
    """Lazy-init the shared TaxonomyExtractor singleton."""
    global _taxonomy
    if _taxonomy is None:
        _taxonomy = TaxonomyExtractor(_TAXONOMY_PATH, nlp=_get_nlp())
    return _taxonomy


# ---------- Semantic search imports with fallback ----------
try:
    import semantic_search

    SEMANTIC_SEARCH_AVAILABLE = True
    # Determine index directory (relative to this file: src/utils/risk_engine.py → ../../indexes)
    SEMANTIC_INDEX_DIR = Path(__file__).parent.parent.parent / "indexes"
    logger.info(f"Semantic search enabled - Index directory: {SEMANTIC_INDEX_DIR}")
except ImportError as e:
    SEMANTIC_SEARCH_AVAILABLE = False
    SEMANTIC_INDEX_DIR = None
    logger.warning(f"Semantic search not available: {e}")

# ---------- temporal plugin loader ----------
try:
    import temporal_proxy as _temporal_proxy  # type: ignore[attr-defined]
except ModuleNotFoundError:
    _tp_spec = importlib.util.spec_from_file_location(
        "temporal_proxy",
        Path(__file__).with_name("temporal_proxy.py"),
    )
    _temporal_proxy = None
    if _tp_spec and _tp_spec.loader:  # pragma: no cover - defensive path
        _temporal_proxy = importlib.util.module_from_spec(_tp_spec)
        sys.modules[_tp_spec.name] = _temporal_proxy  # type: ignore[index]
        _tp_spec.loader.exec_module(_temporal_proxy)  # type: ignore[attr-defined]
    if _temporal_proxy is None:
        raise


# ---------- exceptions ----------
class ConfigError(Exception):
    """Raised when the YAML risk policy is malformed or missing required fields."""

    pass


class ValidationError(Exception):
    """Raised when an input payload fails schema validation."""

    pass


# ---------- safe formula evaluator ----------
class SafeFormulaEvaluator:
    """AST-based safe evaluator for mathematical formulas defined in YAML config.

    This replaces Python's built-in ``eval()`` with a whitelist approach that
    walks the AST and only permits numeric literals, declared variables, basic
    arithmetic operators (+, -, *, /, **), unary +/-, and a small set of
    approved functions (min, max, abs, round).

    Security note:
        No arbitrary code execution is possible through this evaluator.
        Undeclared variable names and unsupported AST node types raise
        ``ValueError`` immediately.
    """

    def __init__(self, variables: dict[str, Any]):
        """
        Initialize evaluator with allowed variables

        Args:
            variables: Dictionary of variable names to values (numbers or functions)
        """
        # Separate functions from values
        self.variables = {}
        self.allowed_functions = {
            "min": min,
            "max": max,
            "abs": abs,
            "round": round,
        }

        for key, value in variables.items():
            if callable(value):
                # Add custom functions
                self.allowed_functions[key] = value
            else:
                # Regular variables
                self.variables[key] = value

    def evaluate(self, formula: str) -> float:
        """
        Safely evaluate a mathematical formula

        Args:
            formula: Math expression like "0.35 * Exploitability + 0.35 * KnownExploited"

        Returns:
            Calculated result

        Raises:
            ValueError: If formula contains disallowed operations
        """
        # Parse formula into AST
        try:
            node = ast.parse(formula, mode="eval")
            result = self._eval_node(node.body)
            return float(result)
        except Exception as e:
            raise ValueError(f"Failed to evaluate formula '{formula}': {e}") from e

    def _eval_node(self, node: ast.AST) -> float:
        """
        Recursively evaluate AST nodes (whitelist approach)

        Only allows: numbers, basic math operators, approved functions, and defined variables
        """
        # Numbers
        if isinstance(node, ast.Constant):
            if isinstance(node.value, int | float):
                return float(node.value)
            raise ValueError(f"Unsupported constant type: {type(node.value)}")

        # Variable names (look up in self.variables)
        elif isinstance(node, ast.Name):
            var_name = node.id
            if var_name in self.variables:
                return float(self.variables[var_name])
            else:
                raise ValueError(f"Undefined variable: {var_name}")

        # Binary operations: +, -, *, /, **
        elif isinstance(node, ast.BinOp):
            left = self._eval_node(node.left)
            right = self._eval_node(node.right)

            if isinstance(node.op, ast.Add):
                return left + right
            elif isinstance(node.op, ast.Sub):
                return left - right
            elif isinstance(node.op, ast.Mult):
                return left * right
            elif isinstance(node.op, ast.Div):
                if right == 0:
                    raise ValueError("Division by zero")
                return left / right
            elif isinstance(node.op, ast.Pow):
                return left**right
            else:
                raise ValueError(f"Unsupported operator: {type(node.op).__name__}")

        # Unary operations: -, +
        elif isinstance(node, ast.UnaryOp):
            operand = self._eval_node(node.operand)
            if isinstance(node.op, ast.USub):
                return -operand
            elif isinstance(node.op, ast.UAdd):
                return +operand
            else:
                raise ValueError(f"Unsupported unary operator: {type(node.op).__name__}")

        # Function calls: min(), max(), abs(), round()
        elif isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name):
                raise ValueError("Only simple function calls allowed")

            func_name = node.func.id
            if func_name not in self.allowed_functions:
                raise ValueError(f"Function '{func_name}' not allowed")

            args = [self._eval_node(arg) for arg in node.args]
            return float(self.allowed_functions[func_name](*args))

        else:
            raise ValueError(f"Unsupported AST node type: {type(node).__name__}")


# ---------- tiny helpers ----------


def clamp(x: float, lo: float, hi: float) -> float:
    """Constrain *x* to the closed interval [*lo*, *hi*]."""
    return max(lo, min(hi, x))


def norm(x: float, a: float, b: float) -> float:
    """Min-max normalize *x* from range [*a*, *b*] into [0, 1], clamped."""
    if b == a:
        return 0.0
    return clamp((x - a) / (b - a), 0.0, 1.0)


def classify_5x5(
    likelihood: float, severity: float, bins: list[float], table: list[list[str]]
) -> str:
    """Map likelihood and severity into a 5×5 risk matrix cell.

    Args:
        likelihood: Normalized likelihood score in [0, 1].
        severity: Normalized severity score in [0, 1].
        bins: Four bin boundaries defining five bands.
        table: 5×5 nested list of risk labels (rows=likelihood, cols=severity).

    Returns:
        Risk classification string (e.g., 'Critical', 'High', 'Medium', 'Low').
    """

    def band(v: float) -> int:
        if v <= bins[0]:
            return 0
        if v <= bins[1]:
            return 1
        if v <= bins[2]:
            return 2
        if v <= bins[3]:
            return 3
        return 4

    return table[band(likelihood)][band(severity)]


# ---------- ICS domain routing ----------

_OT_ICS_KEYWORDS = {
    "scada",
    "plc",
    "rtu",
    "dcs",
    "industrial control",
    "ot network",
    "ics",
    "factory",
    "power plant",
    "substation",
}


_ICS_HINT_LABELS = {
    "ics",
    "ot",
    "ot_ics",
    "industrial",
    "industrial_control",
    "industrial-control",
    "critical_infrastructure",
    "energy",
    "utilities",
    "oil_gas",
    "oil-and-gas",
    "power",
    "power_generation",
    "manufacturing",
    "process_safety",
    "chemical",
    "water_wastewater",
}


_BENIGN_CONTEXT_HINTS = {
    "training cell": 0.6,
    "training": 0.4,
    "test bench": 0.7,
    "demo": 0.4,
    "lab": 0.5,
    "simulator": 0.5,
    "non-production": 0.6,
    "commissioning": 0.4,
    "no intrusion": 0.5,
    "no indicators": 0.4,
    "reboot": 0.3,
    "resolved after reboot": 0.7,
    "maintenance mode": 0.4,
    "maintenance window": 0.3,
}


def _count_ics_keyword_hits(text: str) -> int:
    if not text:
        return 0
    lowered = text.lower()
    hits = 0
    for keyword in _OT_ICS_KEYWORDS:
        if keyword in lowered:
            hits += 1
    return hits


def _should_use_ics_domain(payload: dict[str, Any] | None) -> bool:
    if not payload:
        return False

    def _norm(value: Any) -> str:
        return str(value or "").strip().lower()

    industry_hint = _norm(payload.get("industry"))
    if industry_hint in _ICS_HINT_LABELS or industry_hint.startswith("ot_"):
        return True

    explicit_hint = _norm(payload.get("industry_hint"))
    if explicit_hint in _ICS_HINT_LABELS:
        return True

    asset_type = _norm(payload.get("asset_type"))
    if asset_type in _ICS_HINT_LABELS:
        return True

    text_hits = _count_ics_keyword_hits(
        f"{payload.get('title', '')} {payload.get('description', '')}"
    )
    return text_hits >= 2


def _detect_benign_context(payload: dict[str, Any] | None) -> tuple[float, list[str]]:
    if not payload:
        return 0.0, []

    text = f"{payload.get('title', '')} {payload.get('description', '')}"
    lowered = text.lower()
    score = 0.0
    matches: list[str] = []

    for phrase, weight in _BENIGN_CONTEXT_HINTS.items():
        if phrase in lowered:
            matches.append(phrase)
            score = min(1.0, score + weight)
    return score, matches


def _apply_benign_context_adjustments(
    feature_map: dict[str, float],
    source_map: dict[str, str],
    metadata: dict[str, Any],
    payload: dict[str, Any] | None,
) -> None:
    """Dampen severity features when the threat text describes benign or test contexts.

    Detects phrases like 'training', 'lab', 'simulator', 'non-production'
    and proportionally reduces ``Impact_Category``, ``Data_Sensitivity``,
    and ``Impact_Scope`` — unless those features were set via manual override.

    The dampening factor and affected fields are recorded in the evidence
    chain for transparency.
    """

    benign_score, matches = _detect_benign_context(payload)
    if benign_score <= 0:
        return

    dampener = clamp(1.0 - 0.6 * benign_score, 0.3, 1.0)
    adjusted_fields: dict[str, dict[str, float]] = {}

    for field in ("Impact_Category", "Data_Sensitivity", "Impact_Scope"):
        if field not in feature_map:
            continue
        if source_map.get(field) == "manual_override":
            continue

        original = feature_map[field]
        # Only dampen if score is above a minimal floor to avoid double-penalizing already low scores
        if original <= 0.35:
            continue

        adjusted = clamp(original * dampener, 0.0, original)
        feature_map[field] = adjusted
        adjusted_fields[field] = {"original": round(original, 4), "adjusted": round(adjusted, 4)}

    if not adjusted_fields:
        return

    evidence_entry = {
        "source": "Benign Context Dampener",
        "matches": matches,
        "dampener": round(dampener, 3),
        "adjusted_fields": adjusted_fields,
    }

    evidence_list = metadata.get("evidence")
    if isinstance(evidence_list, list):
        evidence_list.append(evidence_entry)
    else:
        metadata["evidence"] = [evidence_entry]


def _apply_vagueness_dampening(
    feature_map: dict[str, float],
    source_map: dict[str, str],
    metadata: dict[str, Any],
    payload: dict[str, Any] | None,
) -> None:
    """Dampen NLP-derived severity features when the input is short or vague.

    spaCy word-vector similarity is unreliable on very short descriptions
    (< ~10 words): generic terms like "information" or "product" produce
    spurious high-similarity matches against multiple templates.

    This function scales down ``Impact_Category``, ``Data_Sensitivity``,
    and ``Attack_Vector_Exploitability`` when the combined input text is
    below a specificity threshold, unless the feature was set via a
    deterministic database lookup or manual override.
    """

    if not payload:
        return

    text = ((payload.get("title") or "") + " " + (payload.get("description") or "")).strip()
    word_count = len(text.split())

    # No dampening needed for reasonably detailed descriptions
    if word_count >= 15:
        return

    # Scale factor: 1.0 at 15 words, 0.6 at 3 words (linear ramp)
    specificity = clamp((word_count - 3) / 12.0, 0.0, 1.0)
    dampener = 0.6 + 0.4 * specificity  # range [0.6, 1.0]

    nlp_fields = ("Impact_Category", "Data_Sensitivity", "Attack_Vector_Exploitability")
    adjusted_fields: dict[str, dict[str, float]] = {}

    for field in nlp_fields:
        if field not in feature_map:
            continue
        src = (source_map.get(field) or "").lower()
        # Only dampen NLP-derived features, not database or manual overrides
        if src in ("manual_override", "database"):
            continue

        original = feature_map[field]
        if original <= 0.35:
            continue

        adjusted = clamp(original * dampener, 0.0, original)
        feature_map[field] = adjusted
        adjusted_fields[field] = {
            "original": round(original, 4),
            "adjusted": round(adjusted, 4),
        }

    if not adjusted_fields:
        return

    evidence_entry = {
        "source": "Vagueness Dampener",
        "word_count": word_count,
        "dampener": round(dampener, 3),
        "adjusted_fields": adjusted_fields,
    }

    evidence_list = metadata.get("evidence")
    if isinstance(evidence_list, list):
        evidence_list.append(evidence_entry)
    else:
        metadata["evidence"] = [evidence_entry]


# ---------- config ----------
def load_config(path: str) -> dict[str, Any]:
    """Load and validate a YAML risk policy file.

    The configuration must contain at minimum:
        - ``meta.version`` — policy schema version.
        - ``scoring`` — block with likelihood/severity formulas.
        - ``features`` — list of feature definitions with names and defaults.

    The resolved file path is stored as ``__config_file__`` so downstream
    resolvers can locate data files via relative paths.

    Args:
        path: Filesystem path to the YAML config.

    Returns:
        Parsed configuration dictionary.

    Raises:
        ConfigError: If required sections are missing or malformed.
    """
    with open(path, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    if not isinstance(cfg, dict):
        raise ConfigError("YAML root must be a mapping")
    if "meta" not in cfg or "version" not in cfg["meta"]:
        raise ConfigError("Missing meta.version in config")
    if "scoring" not in cfg:
        raise ConfigError("Missing scoring block")
    if "features" not in cfg or not isinstance(cfg["features"], list):
        raise ConfigError("features must be a list")

    # Store config file path for resolving relative paths
    cfg["__config_file__"] = path

    return cfg


# ---------- JSON loader with cache ----------
@lru_cache(maxsize=16)
def _load_json(path: str, base_dir: str = None) -> Any:
    """Load and cache JSON file

    Args:
        path: File path (can be relative or absolute)
        base_dir: Base directory to resolve relative paths from
    """
    from pathlib import Path

    try:
        # Convert to Path object
        file_path = Path(path)

        # If path is relative and base_dir provided, resolve from base_dir
        if not file_path.is_absolute() and base_dir:
            file_path = Path(base_dir) / file_path

        # Try the resolved path
        if file_path.exists():
            with open(file_path, encoding="utf-8") as f:
                return json.load(f)

        # If not found, try common locations relative to project root
        if not file_path.is_absolute():
            # Try from project root (../../ from src/utils)
            project_root = Path(__file__).parent.parent.parent
            alt_path = project_root / path
            if alt_path.exists():
                with open(alt_path, encoding="utf-8") as f:
                    return json.load(f)

        logger.debug(f"Could not find {path}")
        return None

    except FileNotFoundError:
        logger.debug(f"File not found: {path}")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in {path}: {e}")
        return None
    except Exception as e:
        logger.warning(f"Could not load {path}: {e}")
        return None


# ---------- helper for resolving paths ----------
def _get_config_base_dir(cfg: dict[str, Any]) -> str:
    """Get base directory for resolving relative paths in config"""
    from pathlib import Path

    # If config has a __file__ key (added by load_config), use its parent's parent (project root)
    # Config is at policy/risk_rules.hybrid.yaml, so parent.parent gives project root
    if "__config_file__" in cfg:
        return str(Path(cfg["__config_file__"]).parent.parent)
    # Otherwise, try to find project root (two levels up from src/utils/)
    return str(Path(__file__).parent.parent.parent)


# ---------- Indexed lookup caches (C1-C4) ----------
# Built once on first use; O(1) lookups thereafter.

_nvd_index: dict[str, Any] | None = None
_nvd_index_key: str | None = None

_kev_set: set | None = None
_kev_data: dict[str, Any] | None = None
_kev_index_key: str | None = None

_mitre_index: dict[str, tuple] | None = None
_mitre_index_key: str | None = None

_epss_cache: dict[str, tuple] | None = None
_epss_cache_key: str | None = None


def _get_nvd_index(cfg: dict[str, Any]) -> dict[str, Any] | None:
    """Build (once) a ``{cve_id: item}`` dict from the NVD JSON feed."""
    global _nvd_index, _nvd_index_key
    cve_path = cfg.get("sources", {}).get("file_paths", {}).get("cve")
    if not cve_path:
        return None
    key = cve_path
    if _nvd_index is not None and _nvd_index_key == key:
        return _nvd_index
    base_dir = _get_config_base_dir(cfg)
    data = _load_json(cve_path, base_dir)
    if not data:
        return None
    cve_items = data.get("CVE_Items", []) or data.get("vulnerabilities", [])
    index: dict[str, Any] = {}
    for item in cve_items:
        cve_obj = item.get("cve", item)
        cve_id = cve_obj.get("id") or cve_obj.get("CVE_data_meta", {}).get("ID")
        if cve_id:
            index[cve_id] = item
    _nvd_index = index
    _nvd_index_key = key
    logger.info("Built NVD index: %d CVEs", len(index))
    return _nvd_index


def _get_kev_set(cfg: dict[str, Any]) -> tuple[set | None, dict[str, Any] | None]:
    """Build (once) a ``set`` of CVE IDs from the CISA KEV catalog."""
    global _kev_set, _kev_data, _kev_index_key
    kev_path = cfg.get("sources", {}).get("file_paths", {}).get("kev")
    if not kev_path:
        return None, None
    key = kev_path
    if _kev_set is not None and _kev_index_key == key:
        return _kev_set, _kev_data
    base_dir = _get_config_base_dir(cfg)
    data = _load_json(kev_path, base_dir)
    if not data:
        return None, None
    vulns = data.get("vulnerabilities", [])
    cve_set = set()
    vuln_map: dict[str, Any] = {}
    for vuln in vulns:
        cve_id = vuln.get("cveID")
        if cve_id:
            cve_set.add(cve_id)
            vuln_map[cve_id] = vuln
    _kev_set = cve_set
    _kev_data = vuln_map
    _kev_index_key = key
    logger.info("Built KEV index: %d CVEs", len(cve_set))
    return _kev_set, _kev_data


def _get_mitre_index(cfg: dict[str, Any]) -> dict[str, Any] | None:
    """Build (once) a ``{technique_id: stix_object}`` dict from ATT&CK STIX."""
    global _mitre_index, _mitre_index_key
    attack_path = cfg.get("sources", {}).get("file_paths", {}).get("mitre_attack") or cfg.get(
        "sources", {}
    ).get("file_paths", {}).get("attack_enterprise")
    if not attack_path:
        return None
    key = attack_path
    if _mitre_index is not None and _mitre_index_key == key:
        return _mitre_index
    base_dir = _get_config_base_dir(cfg)
    data = _load_json(attack_path, base_dir)
    if not data:
        return None
    index: dict[str, Any] = {}
    for obj in data.get("objects", []):
        if obj.get("type") == "attack-pattern":
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    tid = ref.get("external_id")
                    if tid:
                        index[tid] = obj
                    break
    _mitre_index = index
    _mitre_index_key = key
    logger.info("Built MITRE index: %d techniques", len(index))
    return _mitre_index


def _get_epss_cache(cfg: dict[str, Any]) -> dict[str, tuple] | None:
    """Load (once) the EPSS CSV into a ``{cve_id: (score, percentile)}`` dict."""
    global _epss_cache, _epss_cache_key
    import csv
    import gzip

    epss_path = cfg.get("sources", {}).get("file_paths", {}).get("epss")
    if not epss_path:
        return None
    key = epss_path
    if _epss_cache is not None and _epss_cache_key == key:
        return _epss_cache

    base_dir = _get_config_base_dir(cfg)
    epss_file = Path(base_dir) / epss_path if not Path(epss_path).is_absolute() else Path(epss_path)

    if not epss_file.exists():
        if str(epss_file).endswith(".gz"):
            alt = Path(str(epss_file)[:-3])
            if alt.exists():
                epss_file = alt
        else:
            project_root = Path(__file__).parent.parent.parent
            alt = project_root / epss_path
            if alt.exists():
                epss_file = alt

    if not epss_file.exists():
        return None

    try:
        opener = gzip.open if str(epss_file).endswith(".gz") else open
        cache: dict[str, tuple] = {}
        with opener(epss_file, "rt", encoding="utf-8") as fh:
            # Skip comment lines
            for line in fh:
                if not line.startswith("#"):
                    break
            reader = csv.DictReader([line] + list(fh))
            for row in reader:
                cve_id = (row.get("cve") or "").upper()
                if cve_id:
                    cache[cve_id] = (
                        float(row.get("epss", 0)),
                        float(row.get("percentile", 0)),
                    )
        _epss_cache = cache
        _epss_cache_key = key
        logger.info("Built EPSS index: %d CVEs", len(cache))
        return _epss_cache
    except Exception as exc:
        logger.warning("Failed to build EPSS index: %s", exc)
        return None


# ---------- deterministic resolvers ----------

# -- Shared query embedding cache for deduplication (C5) --
_query_embedding_cache: dict[str, Any] = {}  # {text_hash: np.ndarray}


def _get_query_embedding(description: str):
    """Compute and cache the sentence-transformer embedding for *description*."""
    if not SEMANTIC_SEARCH_AVAILABLE:
        return None
    key = description[:500]  # cache key (truncated for safety)
    if key in _query_embedding_cache:
        return _query_embedding_cache[key]
    try:
        emb = semantic_search.embed_text(description)
        _query_embedding_cache[key] = emb
        return emb
    except Exception:
        return None


def semantic_cve_search(
    description: str, top_k: int = 5, query_embedding=None
) -> list[dict[str, Any]]:
    """
    Semantic search for CVEs when no exact CVE ID is provided.

    Args:
        description: Natural language threat description
        top_k: Number of matches to return
        query_embedding: Optional pre-computed embedding

    Returns:
        List of matched CVEs with similarity scores
    """
    if not SEMANTIC_SEARCH_AVAILABLE:
        logger.warning("Semantic search not available - install sentence-transformers")
        return []

    if not SEMANTIC_INDEX_DIR.exists():
        logger.warning(f"Semantic index not found at {SEMANTIC_INDEX_DIR} - run build_indexes.py")
        return []

    if query_embedding is None:
        query_embedding = _get_query_embedding(description)

    try:
        matches = semantic_search.search_cves(
            description,
            SEMANTIC_INDEX_DIR,
            top_k=top_k,
            min_similarity=0.5,
            query_embedding=query_embedding,
        )
        logger.info(
            f"Semantic CVE search: Found {len(matches)} matches for '{description[:50]}...'"
        )
        return matches
    except Exception as e:
        logger.error(f"Semantic CVE search failed: {e}")
        return []


def semantic_mitre_search(
    description: str, top_k: int = 5, domain: str = "enterprise", query_embedding=None
) -> list[dict[str, Any]]:
    """
    Semantic search for MITRE TTPs when no exact technique ID is provided.

    Args:
        description: Natural language threat description
        top_k: Number of matches to return
        query_embedding: Optional pre-computed embedding

    Returns:
        List of matched TTPs with similarity scores
    """
    if not SEMANTIC_SEARCH_AVAILABLE:
        logger.warning("Semantic search not available - install sentence-transformers")
        return []

    if not SEMANTIC_INDEX_DIR.exists():
        logger.warning(f"Semantic index not found at {SEMANTIC_INDEX_DIR} - run build_indexes.py")
        return []

    if query_embedding is None:
        query_embedding = _get_query_embedding(description)

    try:
        matches = semantic_search.search_mitre_ttps(
            description,
            SEMANTIC_INDEX_DIR,
            top_k=top_k,
            min_similarity=0.5,
            domain=domain,
            query_embedding=query_embedding,
        )
        logger.info(
            f"Semantic MITRE search ({domain}): Found {len(matches)} matches for '{description[:50]}...'"
        )
        return matches
    except Exception as e:
        logger.error(f"Semantic MITRE search failed: {e}")
        return []


def resolve_from_cve(
    cfg: dict[str, Any], input_payload: dict[str, Any]
) -> tuple[dict[str, float], dict[str, Any]]:
    """Extract CVSS scores from the NVD CVE database.

    Supports NVD API formats 1.x and 2.x.  When the input contains a CVE ID,
    performs an exact lookup.  When no CVE ID is present (or the ID is not
    found), falls back to semantic similarity search against the CVE index
    if available.

    Resolved lifecycle metadata (published date, last modified) is attached
    to the evidence record for downstream temporal scoring.

    Returns:
        Tuple of (features dict with CVSS_BaseScore/Exploitability, evidence dict).
    """
    cve_id = input_payload.get("cve")

    # If no CVE ID provided, try semantic search with description
    if not cve_id:
        description = input_payload.get("description", "")
        if description and SEMANTIC_SEARCH_AVAILABLE:
            logger.info("No CVE ID provided - using semantic search")
            matches = semantic_cve_search(
                description, top_k=5, query_embedding=input_payload.get("_query_embedding")
            )

            if matches:
                # Use best match
                best_match = matches[0]
                input_payload["_resolved_cve_id"] = best_match["cve_id"]
                input_payload["_resolved_cve_match"] = best_match
                features = {
                    "CVSS_BaseScore": float(best_match.get("cvss_score", 0)),
                    "CVSS_Exploitability": float(best_match.get("cvss_exploitability", 0)),
                }
                evidence = {
                    "source": "NVD CVE Database (Semantic)",
                    "cve_id": best_match["cve_id"],
                    "similarity": best_match["similarity"],
                    "description": best_match["description"],
                    "features": features,
                    "match_type": "semantic",
                    "all_matches": matches,
                }
                logger.info(
                    f"Semantic CVE match: {best_match['cve_id']} (similarity: {best_match['similarity']:.2%})"
                )
                return features, evidence

        return {}, {}

    # ── O(1) indexed lookup ──
    nvd_idx = _get_nvd_index(cfg)
    if not nvd_idx:
        return {}, {}

    item = nvd_idx.get(cve_id)
    if item is not None:
        # NVD 2.x format: item has 'cve' key
        cve_obj = item.get("cve", item)  # Fallback to item itself for 1.x

        # Capture lifecycle metadata for temporal scoring
        input_payload["_resolved_cve_id"] = cve_id
        published = item.get("published") or item.get("publishedDate") or cve_obj.get("published")
        last_modified = (
            item.get("lastModified") or item.get("lastModifiedDate") or cve_obj.get("lastModified")
        )
        references = cve_obj.get("references", {}) or item.get("references", {})
        reference_urls = []
        if isinstance(references, dict):
            for ref in references.get("reference_data", []):
                url = ref.get("url")
                if url:
                    reference_urls.append(url)

        # NVD 2.x format: metrics at cve.metrics level
        # NVD 1.x format: metrics at item.impact level
        metrics = cve_obj.get("metrics", item.get("impact", {}))

        cvss_version = None
        features = {}
        description = ""

        # Try to get description (NVD 2.x)
        descriptions = cve_obj.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")[:200]
                break

        # Priority: v3.1 > v3.0 > v2.0
        if "cvssMetricV31" in metrics:
            metric = metrics["cvssMetricV31"][0]
            cvss = metric["cvssData"]
            cvss_version = "3.1"
            features = {
                "CVSS_BaseScore": float(cvss.get("baseScore", 0)),
                "CVSS_Exploitability": float(metric.get("exploitabilityScore", 0)),
            }
        elif "cvssMetricV3" in metrics:
            metric = metrics["cvssMetricV3"][0]
            cvss = metric["cvssData"]
            cvss_version = "3.0"
            features = {
                "CVSS_BaseScore": float(cvss.get("baseScore", 0)),
                "CVSS_Exploitability": float(metric.get("exploitabilityScore", 0)),
            }
        elif "cvssMetricV2" in metrics:
            metric = metrics["cvssMetricV2"][0]
            cvss = metric["cvssData"]
            cvss_version = "2.0"
            features = {
                "CVSS_BaseScore": float(cvss.get("baseScore", 0)),
                "CVSS_Exploitability": float(metric.get("exploitabilityScore", 0)),
            }
        elif "baseMetricV31" in metrics:
            cvss = metrics["baseMetricV31"]["cvssV31"]
            cvss_version = "3.1"
            features = {
                "CVSS_BaseScore": float(cvss.get("baseScore", 0)),
                "CVSS_Exploitability": float(cvss.get("exploitabilityScore", 0)),
            }
        elif "baseMetricV3" in metrics:
            cvss = metrics["baseMetricV3"]["cvssV3"]
            cvss_version = "3.0"
            features = {
                "CVSS_BaseScore": float(cvss.get("baseScore", 0)),
                "CVSS_Exploitability": float(cvss.get("exploitabilityScore", 0)),
            }
        elif "baseMetricV2" in metrics:
            cvss = metrics["baseMetricV2"]["cvssV2"]
            cvss_version = "2.0"
            features = {
                "CVSS_BaseScore": float(cvss.get("baseScore", 0)),
                "CVSS_Exploitability": float(cvss.get("exploitabilityScore", 0)),
            }

        if features:
            evidence = {
                "source": "NVD CVE Database",
                "cve_id": cve_id,
                "cvss_version": cvss_version,
                "description": description,
                "features": features,
                "match_type": "exact",
                "published_date": published,
                "last_modified": last_modified,
                "reference_urls": reference_urls[:8],
            }
            logger.debug(f"Found CVE {cve_id}: CVSS={features['CVSS_BaseScore']} (v{cvss_version})")
            return features, evidence

    # Exact match failed - try semantic search if description provided
    description = input_payload.get("description", "")
    if description and SEMANTIC_SEARCH_AVAILABLE:
        logger.info(f"CVE {cve_id} not found - trying semantic search")
        matches = semantic_cve_search(
            description, top_k=5, query_embedding=input_payload.get("_query_embedding")
        )

        if matches:
            # Use the best match (highest similarity)
            best_match = matches[0]
            input_payload["_resolved_cve_id"] = best_match["cve_id"]
            input_payload["_resolved_cve_match"] = best_match
            features = {
                "CVSS_BaseScore": float(best_match.get("cvss_score", 0)),
                "CVSS_Exploitability": float(best_match.get("cvss_exploitability", 0)),
            }
            evidence = {
                "source": "NVD CVE Database (Semantic)",
                "cve_id": best_match["cve_id"],
                "similarity": best_match["similarity"],
                "description": best_match["description"],
                "features": features,
                "match_type": "semantic",
                "all_matches": matches,  # Include all matches for traceability
            }
            logger.info(
                f"Using semantic match: {best_match['cve_id']} (similarity: {best_match['similarity']:.2%})"
            )
            return features, evidence

    logger.debug(f"CVE {cve_id} not found in database and no semantic matches")
    return {}, {}


def resolve_from_kev(
    cfg: dict[str, Any], input_payload: dict[str, Any]
) -> tuple[dict[str, float], dict[str, Any]]:
    """Check whether a CVE appears in the CISA Known Exploited Vulnerabilities catalog.

    Sets ``KnownExploited`` to 1.0 if the CVE is listed (indicating confirmed
    active exploitation), or 0.0 otherwise.  This is a high-signal likelihood
    indicator: KEV-listed CVEs have demonstrated real-world exploitation.

    Returns:
        Tuple of (features dict, evidence dict).
    """
    cve_id = input_payload.get("cve") or input_payload.get("_resolved_cve_id")

    if not cve_id:
        # Try to infer via semantic CVE search to keep KEV resolver independent
        description = input_payload.get("description", "")
        if description and SEMANTIC_SEARCH_AVAILABLE and SEMANTIC_INDEX_DIR.exists():
            logger.info("Inferring CVE for KEV lookup via semantic search")
            _qe = input_payload.get("_query_embedding")
            try:
                matches = semantic_search.search_cves(
                    description,
                    SEMANTIC_INDEX_DIR,
                    top_k=3,
                    min_similarity=0.3,
                    query_embedding=_qe,
                )
                if not matches:
                    matches = semantic_search.search_cves(
                        description,
                        SEMANTIC_INDEX_DIR,
                        top_k=1,
                        min_similarity=0.0,
                        query_embedding=_qe,
                    )
            except Exception as exc:
                logger.warning(f"KEV semantic CVE inference failed: {exc}")
                matches = []

            if matches:
                best_match = matches[0]
                cve_id = best_match.get("cve_id")
                input_payload["_resolved_cve_id"] = cve_id
                input_payload["_resolved_cve_match"] = best_match
    if not cve_id:
        return {}, {}

    # ── O(1) indexed lookup ──
    kev_cve_set, kev_vuln_map = _get_kev_set(cfg)
    if kev_cve_set is None:
        return {}, {}

    if cve_id in kev_cve_set:
        features = {"KnownExploited": 1.0}
        evidence = {
            "source": "CISA KEV Database",
            "cve_id": cve_id,
            "exploit_status": "ACTIVELY EXPLOITED",
            "features": features,
        }
        return features, evidence

    # Not found = not exploited
    features = {"KnownExploited": 0.0}
    evidence = {
        "source": "CISA KEV Database",
        "cve_id": cve_id,
        "exploit_status": "Not in KEV (no known exploitation)",
        "features": features,
    }
    return features, evidence


def resolve_attack_frequency(
    cfg: dict[str, Any], input_payload: dict[str, Any]
) -> tuple[dict[str, float], dict[str, Any]]:
    """Resolve attack frequency from a MITRE ATT&CK technique.

    When a technique ID is provided, performs an exact lookup in the ATT&CK
    STIX bundle and estimates frequency from the number of associated data
    sources.  When no technique ID is present, falls back to semantic
    similarity search against the MITRE index.

    Frequency is dampened when benign-context hints (e.g., 'training',
    'lab', 'simulator') are detected in the payload text.

    Returns:
        Tuple of (features dict with Attack_Frequency, evidence dict).
    """
    ttx = input_payload.get("ttx")
    mitre_domain = "ics" if _should_use_ics_domain(input_payload) else "enterprise"
    semantic_source = (
        "MITRE ATT&CK ICS (Semantic)" if mitre_domain == "ics" else "MITRE ATT&CK (Semantic)"
    )

    # If no TTX provided, try semantic search
    if not ttx:
        description = input_payload.get("description", "")
        if description and SEMANTIC_SEARCH_AVAILABLE:
            logger.info("No MITRE TTP provided - using semantic search")
            matches = semantic_mitre_search(
                description,
                top_k=5,
                domain=mitre_domain,
                query_embedding=input_payload.get("_query_embedding"),
            )

            if matches:
                # Use best match and calculate frequency based on similarity
                best_match = matches[0]
                similarity = best_match["similarity"]

                # Convert similarity to attack frequency (0.5-1.0 range for good matches)
                frequency = 0.5 + (similarity * 0.5)  # 50% sim → 0.75 freq, 100% sim → 1.0 freq
                benign_score, benign_matches = _detect_benign_context(input_payload)
                benign_details = None
                if benign_score > 0:
                    dampener = 1.0 - 0.5 * benign_score
                    frequency = clamp(frequency * dampener, 0.0, 1.0)
                    benign_details = {"matches": benign_matches, "dampener": round(dampener, 3)}

                features = {"Attack_Frequency": float(frequency)}
                evidence = {
                    "source": semantic_source,
                    "technique_id": best_match["technique_id"],
                    "technique_name": best_match["name"],
                    "similarity": similarity,
                    "tactics": best_match.get("tactics", []),
                    "match_type": "semantic",
                    "all_matches": matches,
                    "features": features,
                }
                if benign_details:
                    evidence["benign_context"] = benign_details
                logger.info(
                    f"Semantic MITRE match: {best_match['technique_id']} - {best_match['name']} (similarity: {similarity:.2%}, freq: {frequency:.2f})"
                )
                return features, evidence

        return {}, {}

    # ── O(1) indexed lookup ──
    mitre_idx = _get_mitre_index(cfg)
    if not mitre_idx:
        return {}, {}

    obj = mitre_idx.get(ttx)
    if obj is not None:
        frequency = obj.get("frequency", 0.5)
        if "x_mitre_data_sources" in obj:
            ds_count = len(obj.get("x_mitre_data_sources", []))
            frequency = min(1.0, ds_count / 10.0)

        technique_name = obj.get("name", "Unknown")
        features = {"Attack_Frequency": float(frequency)}
        evidence = {
            "source": "MITRE ATT&CK",
            "technique_id": ttx,
            "technique_name": technique_name,
            "data_sources": len(obj.get("x_mitre_data_sources", [])),
            "match_type": "exact",
            "features": features,
        }
        benign_score, benign_matches = _detect_benign_context(input_payload)
        if benign_score > 0:
            dampener = 1.0 - 0.5 * benign_score
            features["Attack_Frequency"] = clamp(features["Attack_Frequency"] * dampener, 0.0, 1.0)
            evidence["benign_context"] = {"matches": benign_matches, "dampener": round(dampener, 3)}
        return features, evidence

    # Exact TTX not found - try semantic search
    description = input_payload.get("description", "")
    if description and SEMANTIC_SEARCH_AVAILABLE:
        logger.info(f"MITRE TTP {ttx} not found - trying semantic search")
        matches = semantic_mitre_search(
            description,
            top_k=5,
            domain=mitre_domain,
            query_embedding=input_payload.get("_query_embedding"),
        )

        if matches:
            best_match = matches[0]
            similarity = best_match["similarity"]
            frequency = 0.5 + (similarity * 0.5)
            benign_score, benign_matches = _detect_benign_context(input_payload)
            benign_details = None
            if benign_score > 0:
                dampener = 1.0 - 0.5 * benign_score
                frequency = clamp(frequency * dampener, 0.0, 1.0)
                benign_details = {"matches": benign_matches, "dampener": round(dampener, 3)}

            features = {"Attack_Frequency": float(frequency)}
            evidence = {
                "source": semantic_source,
                "technique_id": best_match["technique_id"],
                "technique_name": best_match["name"],
                "similarity": similarity,
                "tactics": best_match.get("tactics", []),
                "match_type": "semantic",
                "all_matches": matches,
                "features": features,
            }
            if benign_details:
                evidence["benign_context"] = benign_details
            logger.info(
                f"Semantic MITRE match: {best_match['technique_id']} (similarity: {similarity:.2%})"
            )
            return features, evidence

    return {}, {}


def resolve_emb3d_maturity(
    cfg: dict[str, Any], input_payload: dict[str, Any]
) -> tuple[dict[str, float], dict[str, Any]]:
    """Resolve system maturity from EMB3D threat model

    Returns:
        (features_dict, evidence_dict)
    """
    asset = input_payload.get("asset", "").lower()
    if not asset:
        return {}, {}

    emb3d_path = cfg.get("sources", {}).get("file_paths", {}).get("emb3d")
    if not emb3d_path:
        return {}, {}

    base_dir = _get_config_base_dir(cfg)
    data = _load_json(emb3d_path, base_dir)
    if not data:
        return {}, {}

    # EMB3D STIX format - look for device/platform indicators
    objects = data.get("objects", [])
    for obj in objects:
        name = obj.get("name", "").lower()
        if asset in name or name in asset:
            # Estimate maturity from threat model completeness
            # More properties = more mature threat model
            props_count = len(obj.get("x_mitre_platforms", [])) + len(
                obj.get("x_mitre_data_sources", [])
            )
            maturity_level = min(1.0, props_count / 20.0)

            features = {"System_Maturity": 1.0 - maturity_level}
            evidence = {
                "source": "EMB3D Threat Model",
                "asset": asset,
                "matched_threat": name,
                "maturity_indicators": props_count,
                "features": features,
            }
            return features, evidence

    return {}, {}


def resolve_internal_safety(
    cfg: dict[str, Any], input_payload: dict[str, Any], *, doc=None
) -> tuple[dict[str, float], dict[str, Any]]:
    """Detect safety-relevant impact from threat description keywords.

    Delegates to ``TaxonomyExtractor`` for keyword matching against the
    ``safety`` section of ``taxonomy.yaml``.  Also checks internal reports
    database when configured.

    Args:
        doc: Optional pre-parsed spaCy ``Doc`` (invalidated if internal
             reports text is appended).

    Returns:
        Tuple of (features dict with Safety_Impact_Flag, evidence dict).
    """
    title = input_payload.get("title", "").lower()
    description = input_payload.get("description", "").lower()
    combined_text = f"{title} {description}"

    # Optionally check internal reports database if it exists
    pentest_path = cfg.get("sources", {}).get("file_paths", {}).get("internal_pentest") or cfg.get(
        "sources", {}
    ).get("file_paths", {}).get("internal_reports")
    if pentest_path:
        base_dir = _get_config_base_dir(cfg)
        data = _load_json(pentest_path, base_dir)
        if data:
            reports = data if isinstance(data, list) else data.get("reports", [])
            for report in reports:
                report_text = f"{report.get('title', '')} {report.get('description', '')}".lower()
                combined_text += f" {report_text}"
            # Text was extended — invalidate pre-parsed doc
            doc = None

    return _get_taxonomy().extract(
        "safety", combined_text, cfg=cfg, input_payload=input_payload, doc=doc
    )


def resolve_from_epss(
    cfg: dict[str, Any], input_payload: dict[str, Any]
) -> tuple[dict[str, float], dict[str, Any]]:
    """Retrieve EPSS exploit probability and percentile for a CVE.

    EPSS (Exploit Prediction Scoring System) predicts the probability that a
    vulnerability will be exploited in the wild within the next 30 days.
    Higher values indicate greater exploitation likelihood.

    Uses a cached in-memory dict for O(1) lookups after the first load.

    Returns:
        Tuple of (features dict with EPSS_Score/EPSS_Percentile, evidence dict).
    """
    cve_id = input_payload.get("cve")
    if not cve_id:
        return {}, {}

    cache = _get_epss_cache(cfg)
    if cache is None:
        return {}, {}

    entry = cache.get(cve_id.upper())
    if entry is None:
        return {}, {}

    epss_score, percentile = entry
    features = {"EPSS_Score": epss_score, "EPSS_Percentile": percentile}
    evidence = {
        "source": "EPSS Database",
        "cve_id": cve_id,
        "epss_score": epss_score,
        "percentile": percentile,
        "interpretation": f"Top {int((1-percentile)*100)}% most likely to be exploited",
        "features": features,
    }
    return features, evidence


def extract_attack_vector_exploitability(
    cfg: dict[str, Any], input_payload: dict[str, Any], *, doc=None
) -> tuple[dict[str, float], dict[str, Any]]:
    """Score exploitability based on the attack vector described in the threat text.

    Delegates to ``TaxonomyExtractor`` (``attack_vector`` section).
    NLP semantic similarity is tried first, falling back to keyword matching.

    Returns:
        Tuple of (features dict with Attack_Vector_Exploitability, evidence dict).
    """
    description = (
        input_payload.get("title", "") + " " + input_payload.get("description", "")
    ).lower()
    return _get_taxonomy().extract(
        "attack_vector", description, cfg=cfg, input_payload=input_payload, doc=doc
    )


def extract_temporal_context(
    cfg: dict[str, Any], input_payload: dict[str, Any]
) -> tuple[dict[str, float], dict[str, Any]]:
    """Detect whether the threat describes a past incident or an active/potential threat.

    Past incidents (already occurred) receive a ``Temporal_Likelihood_Modifier``
    of 0.5-1.0, reducing their likelihood score since they represent historical
    events rather than future exploitation probability.  Active threat indicators
    leave the modifier at 1.0.

    Returns:
        Tuple of (features dict with Temporal_Likelihood_Modifier, evidence dict).
    """
    description = (
        input_payload.get("title", "") + " " + input_payload.get("description", "")
    ).lower()

    # Past tense indicators
    past_tense_patterns = [
        # Past actions - definite incidents
        "was encrypted",
        "were encrypted",
        "has been encrypted",
        "had been encrypted",
        "was compromised",
        "were compromised",
        "has been compromised",
        "had been compromised",
        "was exploited",
        "were exploited",
        "has been exploited",
        "was breached",
        "were breached",
        "has been breached",
        "was infected",
        "were infected",
        "has been infected",
        "was attacked",
        "were attacked",
        "has been attacked",
        "occurred",
        "happened",
        "took place",
        # Incident response indicators
        "operations down for",
        "downtime of",
        "systems were down",
        "resulted in",
        "caused by",
        "led to",
        # Time indicators
        "yesterday",
        "last week",
        "last month",
        "days ago",
        "weeks ago",
        "on [date]",
        "in [month]",
        "earlier this",
    ]

    # Present/Future tense indicators - active threats
    active_threat_patterns = [
        "can be",
        "could be",
        "may be",
        "might be",
        "allows",
        "enables",
        "permits",
        "vulnerable to",
        "potential for",
        "possible to",
        "able to",
        "exposes",
        "risks",
        "threatens",
        "actively exploited",
        "being exploited",
        "under attack",
        "zero-day",
        "unpatched",
        "newly discovered",
    ]

    past_score = 0
    active_score = 0
    matched_past = []
    matched_active = []

    for pattern in past_tense_patterns:
        if pattern in description:
            past_score += 1
            matched_past.append(pattern)

    for pattern in active_threat_patterns:
        if pattern in description:
            active_score += 1
            matched_active.append(pattern)

    # Determine temporal context
    if past_score > active_score and past_score >= 1:
        # Past incident - reduce likelihood
        temporal_modifier = 0.5  # 50% reduction for historical incidents
        context = "past_incident"
        interpretation = "Historical incident - already occurred"
    elif active_score > past_score and active_score >= 1:
        # Active threat - no reduction
        temporal_modifier = 1.0
        context = "active_threat"
        interpretation = "Active/potential threat - could occur"
    else:
        # Neutral/unclear - no modification
        temporal_modifier = 1.0
        context = "unclear"
        interpretation = "Temporal context unclear"

    features = {"Temporal_Likelihood_Modifier": temporal_modifier}
    evidence = {
        "source": "Temporal Context Analysis",
        "context": context,
        "interpretation": interpretation,
        "past_indicators": matched_past[:3],
        "active_indicators": matched_active[:3],
        "modifier": temporal_modifier,
        "confidence": 0.8 if (past_score >= 2 or active_score >= 2) else 0.5,
        "features": features,
    }

    return features, evidence


# ---------- Taxonomy-driven Feature Extractors ----------
# All classification patterns now live in policy/taxonomy.yaml.
# These thin wrappers delegate to TaxonomyExtractor for NLP + keyword matching.


def extract_impact_category(
    cfg: dict[str, Any], input_payload: dict[str, Any], *, doc=None
) -> tuple[dict[str, float], dict[str, Any]]:
    """Extract impact severity category from the threat description.

    Delegates to ``TaxonomyExtractor`` (``impact_category`` section).
    NLP semantic similarity + dependency parsing tried first, keyword fallback second.

    Returns:
        Tuple of (features dict with Impact_Category, evidence dict).
    """
    description = (
        input_payload.get("title", "") + " " + input_payload.get("description", "")
    ).lower()
    return _get_taxonomy().extract(
        "impact_category", description, cfg=cfg, input_payload=input_payload, doc=doc
    )


def extract_data_sensitivity(
    cfg: dict[str, Any], input_payload: dict[str, Any], *, doc=None
) -> tuple[dict[str, float], dict[str, Any]]:
    """Assess data sensitivity from the threat description.

    Delegates to ``TaxonomyExtractor`` (``data_sensitivity`` section).
    NLP semantic similarity tried first, keyword fallback second.

    Returns:
        Tuple of (features dict with Data_Sensitivity, evidence dict).
    """
    description = (
        input_payload.get("title", "") + " " + input_payload.get("description", "")
    ).lower()
    return _get_taxonomy().extract(
        "data_sensitivity", description, cfg=cfg, input_payload=input_payload, doc=doc
    )


def extract_impact_scope(
    cfg: dict[str, Any], input_payload: dict[str, Any], *, doc=None
) -> tuple[dict[str, float], dict[str, Any]]:
    """Estimate the blast radius of a threat from description text.

    Delegates to ``TaxonomyExtractor`` (``impact_scope`` section).
    Uses NLP POS-aware token matching + numerical detection first,
    keyword fallback second.

    Returns:
        Tuple of (features dict with Impact_Scope, evidence dict).
    """
    description = (
        input_payload.get("title", "") + " " + input_payload.get("description", "")
    ).lower()

    # Impact scope uses token-level matching, not cosine similarity
    nlp = _get_nlp()
    if nlp is not None:
        nlp_score, nlp_evidence = _get_taxonomy().extract_scope_nlp(description, doc=doc)
        if nlp_score is not None:
            features = {"Impact_Scope": nlp_score}
            evidence = {
                "source": "Impact Scope Extraction (NLP)",
                "matched_scope": nlp_evidence.get("method", "semantic"),
                "all_matches": [
                    nlp_evidence.get("keyword") or nlp_evidence.get("entity_type", "detected")
                ],
                "score": nlp_score,
                "confidence": nlp_evidence.get("confidence", 0.85),
            }
            return features, evidence

    return _get_taxonomy().extract(
        "impact_scope", description, cfg=cfg, input_payload=input_payload, doc=doc
    )


def deterministic_features_from_dbs(
    cfg: dict[str, Any], input_payload: dict[str, Any]
) -> tuple[dict[str, float], list[dict[str, Any]]]:
    """Run all registered resolvers and merge their feature outputs.

    Each resolver independently queries a data source (NVD, KEV, MITRE, EPSS,
    NLP extractors) and returns a
    ``(features, evidence)`` tuple.  This function orchestrates all resolvers,
    merges feature dictionaries (last-write-wins for overlapping keys within
    the resolver layer), and aggregates evidence records into a single list.

    Args:
        cfg: Loaded risk policy configuration.
        input_payload: Threat input containing title, description, CVE, etc.

    Returns:
        Tuple of (merged feature dict, list of evidence records).
    """
    features: dict[str, float] = {}
    evidence_list: list[dict[str, Any]] = []

    # ── Parse the description once for all NLP-backed extractors ──
    desc_text = (
        input_payload.get("title", "") + " " + input_payload.get("description", "")
    ).lower()
    nlp = _get_nlp()
    desc_doc = nlp(desc_text) if nlp is not None else None

    # ── Compute the sentence-transformer embedding once (C5) ──
    if SEMANTIC_SEARCH_AVAILABLE and "_query_embedding" not in input_payload:
        input_payload["_query_embedding"] = _get_query_embedding(desc_text)

    # Resolvers that do NOT use the shared doc (they have their own lookups)
    db_resolvers = [
        ("NVD CVE", resolve_from_cve),
        ("CISA KEV", resolve_from_kev),
        ("MITRE ATT&CK", resolve_attack_frequency),
        ("EMB3D", resolve_emb3d_maturity),
        ("EPSS", resolve_from_epss),
        ("Temporal Context", extract_temporal_context),
    ]

    for name, resolver_func in db_resolvers:
        try:
            resolved_features, evidence = resolver_func(cfg, input_payload)
            if resolved_features:
                features.update(resolved_features)
            if evidence:
                if isinstance(evidence, list):
                    evidence_list.extend(evidence)
                else:
                    evidence_list.append(evidence)
        except Exception as e:
            logger.warning("Error in %s resolver: %s", name, e)

    # Resolvers that accept a pre-parsed spaCy doc (parse once, use many)
    nlp_resolvers = [
        ("Safety Keywords", resolve_internal_safety),
        ("Attack Vector", extract_attack_vector_exploitability),
        ("Impact Category", extract_impact_category),
        ("Data Sensitivity", extract_data_sensitivity),
        ("Impact Scope", extract_impact_scope),
    ]

    for name, resolver_func in nlp_resolvers:
        try:
            resolved_features, evidence = resolver_func(cfg, input_payload, doc=desc_doc)
            if resolved_features:
                features.update(resolved_features)
            if evidence:
                if isinstance(evidence, list):
                    evidence_list.extend(evidence)
                else:
                    evidence_list.append(evidence)
        except Exception as e:
            logger.warning("Error in %s resolver: %s", name, e)

    return features, evidence_list


# ---------- feature assembly (defaults + overrides) ----------
def _feature_defaults(cfg: dict[str, Any]) -> dict[str, float]:
    vals: dict[str, float] = {}
    for f in cfg.get("features", []):
        name = f["name"]
        vals[name] = float(f.get("default", 0))
    return vals


def build_features(
    cfg: dict[str, Any], overrides: dict[str, Any], input_payload: dict[str, Any] = None
) -> tuple[dict[str, float], dict[str, Any]]:
    """Assemble the complete feature vector for scoring.

    Feature values are layered with increasing priority:
        1. YAML-defined defaults (lowest).
        2. Values resolved from intelligence databases.
        3. Manual overrides supplied by the caller (highest).

    The returned metadata tracks provenance for every feature via
    ``source_map`` (default | database | manual_override) and includes the
    full evidence chain from all resolvers.

    Args:
        cfg: Loaded risk policy configuration.
        overrides: Caller-supplied feature overrides (may be empty).
        input_payload: Threat input dict; ``None`` skips resolver enrichment.

    Returns:
        Tuple of (feature dict mapping names to floats, metadata dict).
    """
    vals = _feature_defaults(cfg)
    evidence_list = []
    source_map = {}  # Track where each feature came from

    # Mark defaults
    for key in vals:
        source_map[key] = "default"

    # Apply DB-resolved values if payload provided
    if input_payload:
        db_features, evidence_list = deterministic_features_from_dbs(cfg, input_payload)
        for key, value in db_features.items():
            vals[key] = value
            source_map[key] = "database"

    # Apply manual overrides (highest priority)
    for k, v in (overrides or {}).items():
        if k in vals:
            vals[k] = float(v)
            source_map[k] = "manual_override"

    # Calculate confidence (% of features from databases)
    total_features = len(vals)
    db_features_count = sum(1 for src in source_map.values() if src == "database")
    confidence = db_features_count / total_features if total_features > 0 else 0.0

    metadata = {
        "evidence": evidence_list,
        "source_map": source_map,
        "confidence": confidence,
        "db_features_count": db_features_count,
        "total_features": total_features,
    }

    if input_payload:
        _apply_benign_context_adjustments(vals, source_map, metadata, input_payload)
        _apply_vagueness_dampening(vals, source_map, metadata, input_payload)

    if input_payload:
        _attach_temporal_risk(metadata, vals, input_payload)

    return vals, metadata


# ---------- scoring ----------
def compute_scores(
    cfg: dict[str, Any], features: dict[str, float], context: dict[str, Any]
) -> dict[str, Any]:
    """Evaluate likelihood and severity formulas and classify overall risk.

    Likelihood and severity are computed independently using the formulas
    declared in the ``scoring`` block of the risk policy YAML.  Severity
    operates in dual-mode: ``with_cvss_formula`` is used when
    ``CVSS_BaseScore > 0``, otherwise ``without_cvss_formula`` applies.

    Both scores are clamped to [0, 1] and then mapped through a configurable
    5×5 matrix to produce the final ``overall_risk`` classification.

    Args:
        cfg: Loaded risk policy configuration.
        features: Feature dict (output of ``build_features``).
        context: Contextual overrides such as ``asset_type``.

    Returns:
        Dict with ``likelihood``, ``severity``, ``overall_risk``,
        ``severity_mode``, ``context_criticality``, and ``feature_breakdown``.

    Raises:
        ConfigError: If a formula string cannot be parsed or evaluated.
    """
    # Prepare variables for formula evaluation
    variables = {"norm": norm, "min": min, "max": max, "clamp": clamp}
    variables.update(features)
    variables.update(context or {})

    # Create safe evaluator
    evaluator = SafeFormulaEvaluator(variables)

    # Evaluate likelihood formula
    like_expr = cfg["scoring"]["likelihood"]["formula"]
    like_expr = " ".join(like_expr.split())  # Clean up formatting

    try:
        likelihood = evaluator.evaluate(like_expr)
    except ValueError as e:
        raise ConfigError(f"Invalid likelihood formula: {e}") from e

    lo, hi = cfg["scoring"]["likelihood"]["clamp"]
    likelihood = clamp(likelihood, float(lo), float(hi))

    # Severity (+ context_criticality from config)
    # Dual-mode: use with_cvss if CVSS_BaseScore > 0, otherwise without_cvss
    sev_cfg = cfg["scoring"]["severity"]
    ctx_cfg = sev_cfg.get("context_criticality", {})
    cc_default = float(ctx_cfg.get("default", 0.5))
    by_asset = ctx_cfg.get("by_asset", {})
    asset_type = (context or {}).get("asset_type")
    context_criticality = float(by_asset.get(asset_type, cc_default))

    # Add context_criticality to variables for severity formula
    variables["context_criticality"] = context_criticality
    evaluator_sev = SafeFormulaEvaluator(variables)

    # Determine which formula to use
    has_cvss = features.get("CVSS_BaseScore", 0) > 0
    severity_mode = "with_cvss" if has_cvss else "without_cvss"

    if has_cvss:
        sev_expr = sev_cfg.get("with_cvss_formula", sev_cfg.get("formula", ""))
    else:
        sev_expr = sev_cfg.get("without_cvss_formula", sev_cfg.get("formula", ""))

    # Evaluate severity formula
    sev_expr = " ".join(sev_expr.split())  # Clean up formatting

    try:
        severity = evaluator_sev.evaluate(sev_expr)
    except ValueError as e:
        raise ConfigError(f"Invalid severity formula: {e}") from e

    slo, shi = sev_cfg["clamp"]
    severity = clamp(severity, float(slo), float(shi))

    # 5x5 overall
    mat = cfg["scoring"]["overall_risk"]["matrix"]
    overall = classify_5x5(likelihood, severity, mat["bins"], mat["table"])

    return {
        "likelihood": round(likelihood, 4),
        "severity": round(severity, 4),
        "overall_risk": overall,
        "context_criticality": context_criticality,
        "severity_mode": severity_mode,
        "feature_breakdown": features,
    }


# ---------------------------------------------------------------------------
# Temporal risk (Patent Pending IP — internal use only)
# ---------------------------------------------------------------------------


def _parse_iso8601(value: str | None) -> datetime | None:
    """Parse ISO8601 or date strings into timezone-aware datetimes."""
    if not value:
        return None

    cleaned = value.strip()
    if not cleaned:
        return None

    # Normalize trailing Z
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(cleaned)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        pass

    formats = [
        "%Y-%m-%d",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
    ]

    for fmt in formats:
        try:
            dt = datetime.strptime(value, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _extract_temporal_context(
    metadata: dict[str, Any],
    features: dict[str, float],
    input_payload: dict[str, Any],
) -> dict[str, Any] | None:
    cve_id = (input_payload or {}).get("cve")
    base_score = features.get("CVSS_BaseScore")
    if not cve_id or not base_score:
        return None

    evidence_list = (metadata or {}).get("evidence", []) or []
    published: str | None = None
    last_modified: str | None = None
    epss_score: float | None = features.get("EPSS_Score")
    kev_listed = False

    for ev in evidence_list:
        source = ev.get("source")
        if source == "NVD CVE Database":
            published = ev.get("published_date") or published
            last_modified = ev.get("last_modified") or last_modified
        elif source == "EPSS Database" and epss_score is None:
            epss_score = ev.get("epss_score")
        elif source == "CISA KEV Database":
            status = str(ev.get("exploit_status", "")).lower()
            if "active" in status or ev.get("features", {}).get("KnownExploited") == 1.0:
                kev_listed = True

    disclosure_dt = _parse_iso8601(published)
    if disclosure_dt is None:
        return None

    context = {
        "base_score": base_score,
        "disclosure_date": disclosure_dt,
        "current_date": datetime.now(timezone.utc),
        "epss_score": epss_score if epss_score is not None else 0.5,
        "known_exploited": features.get("KnownExploited", 0.0) >= 0.5,
        "kev_listed": kev_listed,
        "last_modified": _parse_iso8601(last_modified),
        "adoption_hint": metadata.get("confidence"),
        "cve_id": cve_id,
    }

    return context


def _attach_temporal_risk(
    metadata: dict[str, Any], features: dict[str, float], input_payload: dict[str, Any]
) -> None:
    try:
        if not _temporal_proxy.temporal_plugin_ready():
            status = _temporal_proxy.temporal_plugin_status()
            if status and "temporal_risk_status" not in metadata:
                metadata["temporal_risk_status"] = status
            return

        context = _extract_temporal_context(metadata, features, input_payload or {})
        if not context:
            return

        calculator = _temporal_proxy.get_temporal_calculator()
        result = calculator.calculate(**context)
        if result:
            metadata["temporal_risk"] = result
    except Exception as exc:  # pragma: no cover - defensive guardrail
        logger.debug(f"Temporal risk calculation skipped: {exc}")
