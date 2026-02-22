"""Generic taxonomy-driven feature extractor for the DetRisk risk engine.

This module replaces the per-feature hardcoded template dictionaries and keyword
lists with a single data-driven pipeline.  All classification patterns live in
``policy/taxonomy.yaml``; this code is the *interpreter*.

Usage in ``risk_engine.py``::

    from feature_extractor import TaxonomyExtractor

    _extractor = TaxonomyExtractor("../../policy/taxonomy.yaml")
    features, evidence = _extractor.extract("attack_vector", description)

Design:
    * NLP (spaCy semantic similarity) is tried first when available.
    * Falls back to substring keyword matching automatically.
    * Each extractor key in taxonomy.yaml declares its own thresholds,
      scoring mode, boost rules, and keyword/template lists.
    * Adding a new threat category = adding YAML lines, zero code changes.
"""

from __future__ import annotations

import re
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, value))


def _interpret_label(score: float) -> str:
    if score >= 0.8:
        return "Very High"
    if score >= 0.6:
        return "High"
    if score >= 0.4:
        return "Medium"
    return "Low"


# ---------------------------------------------------------------------------
# Core class
# ---------------------------------------------------------------------------

class TaxonomyExtractor:
    """Data-driven feature extractor backed by ``taxonomy.yaml``.

    Each call to :meth:`extract` resolves a single feature (e.g.
    ``attack_vector``, ``impact_category``) by:

    1. Running spaCy semantic similarity against NLP templates (if available).
    2. Falling back to keyword substring matching.
    3. Applying scoring rules (boosts, multi-match modes) from the YAML
       ``settings`` block.

    The class caches the parsed taxonomy so repeated calls are cheap.
    """

    def __init__(self, taxonomy_path: str | Path, nlp=None):
        """
        Args:
            taxonomy_path: Path to ``taxonomy.yaml``.
            nlp: A loaded spaCy language model (or ``None`` to skip NLP).
        """
        self._path = Path(taxonomy_path)
        self._nlp = nlp
        self._taxonomy: Dict[str, Any] = {}
        self._nlp_doc_cache: Dict[str, Any] = {}
        self._load()

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _load(self) -> None:
        with self._path.open("r", encoding="utf-8") as fh:
            self._taxonomy = yaml.safe_load(fh) or {}
        logger.debug("Loaded taxonomy with %d extractors", len(self._taxonomy))

    def reload(self) -> None:
        """Re-read taxonomy from disk (useful after edits)."""
        self._load()
        self._nlp_doc_cache.clear()

    @property
    def extractor_names(self) -> List[str]:
        return list(self._taxonomy.keys())

    def get_section(self, name: str) -> Dict[str, Any]:
        """Return the raw taxonomy section for *name*."""
        return self._taxonomy.get(name, {})

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract(
        self,
        extractor_name: str,
        text: str,
        *,
        cfg: Optional[Dict[str, Any]] = None,
        input_payload: Optional[Dict[str, Any]] = None,
        doc: Any = None,
    ) -> Tuple[Dict[str, float], Dict[str, Any]]:
        """Run a named extractor against *text*.

        Args:
            doc: An optional pre-parsed spaCy ``Doc`` for *text*. When
                 supplied, the extractor skips redundant ``nlp(text)`` calls.

        Returns:
            ``(features_dict, evidence_dict)`` — both empty if nothing matched.
        """
        section = self._taxonomy.get(extractor_name)
        if not section:
            logger.warning("Unknown extractor: %s", extractor_name)
            return {}, {}

        feature_name: str = section["feature"]
        settings: Dict[str, Any] = section.get("settings", {})

        # ---- special-case: impact_category prevention short-circuit ----
        if extractor_name == "impact_category":
            result = self._check_prevention(section, text, doc=doc)
            if result is not None:
                return {feature_name: result[0]}, result[1]

        # ---- NLP path ----
        if self._nlp is not None and "nlp_templates" in section:
            result = self._extract_nlp(section, text, settings, doc=doc)
            if result is not None:
                score, evidence = result
                return {feature_name: score}, evidence

        # ---- dependency-parse patterns (impact_category only for now) ----
        if self._nlp is not None and "dependency_patterns" in section:
            result = self._check_dependency_patterns(section, text, doc=doc)
            if result is not None:
                return {feature_name: result[0]}, result[1]

        # ---- keyword fallback ----
        if "keywords" in section:
            result = self._extract_keywords(section, text, settings)
            if result is not None:
                score, evidence = result
                return {feature_name: score}, evidence

        return {}, {}

    def extract_scope_nlp(
        self,
        text: str,
        *,
        doc: Any = None,
    ) -> Tuple[Optional[float], Dict[str, Any]]:
        """Dedicated scope extractor using NLP token + numerical matching.

        Impact scope uses POS-aware token matching and regex number detection
        rather than cosine similarity, so it needs its own path.

        Args:
            doc: Optional pre-parsed spaCy ``Doc``.
        """
        section = self._taxonomy.get("impact_scope")
        if not section or self._nlp is None:
            return None, {}

        if doc is None:
            doc = self._nlp(text.lower())

        max_score = 0.0
        evidence: Dict[str, Any] = {}

        # 1. Numerical entity detection
        numbers_pattern = r'\b(\d+)\s+(systems?|servers?|machines?|hosts?|devices?|users?|customers?)\b'
        for match in re.finditer(numbers_pattern, text.lower()):
            count = int(match.group(1))
            entity_type = match.group(2)
            score = self._count_to_score(section, count)
            if score > max_score:
                max_score = score
                evidence = {
                    "method": "numerical_detection",
                    "count": count,
                    "entity_type": entity_type,
                    "confidence": 0.95,
                }

        # 2. POS-aware scope indicators
        indicators = section.get("nlp_scope_indicators", {})
        for token in doc:
            if token.text in indicators:
                score = indicators[token.text]
                if token.head.pos_ == "NOUN" and score > max_score:
                    max_score = score
                    evidence = {
                        "method": "scope_keyword",
                        "keyword": token.text,
                        "modified_noun": token.head.text,
                        "confidence": 0.85,
                    }

        if max_score > 0:
            return max_score, evidence
        return None, {}

    # ------------------------------------------------------------------
    # Internal: NLP similarity
    # ------------------------------------------------------------------

    def _get_template_doc(self, template_text: str):
        """Cache spaCy docs for template strings."""
        if template_text not in self._nlp_doc_cache:
            self._nlp_doc_cache[template_text] = self._nlp(template_text)
        return self._nlp_doc_cache[template_text]

    def _extract_nlp(
        self,
        section: Dict[str, Any],
        text: str,
        settings: Dict[str, Any],
        *,
        doc: Any = None,
    ) -> Optional[Tuple[float, Dict[str, Any]]]:
        threshold = settings.get("nlp_threshold", 0.65)
        if doc is None:
            doc = self._nlp(text.lower())

        best_sim = 0.0
        best_name: Optional[str] = None
        best_base_score = 0.0

        for name, tmpl in section["nlp_templates"].items():
            tmpl_doc = self._get_template_doc(tmpl["text"])
            sim = doc.similarity(tmpl_doc)
            if sim > best_sim:
                best_sim = sim
                best_name = name
                best_base_score = tmpl["score"]

        if best_sim < threshold or best_name is None:
            return None

        # Adjust score by similarity strength
        score_scale = 0.7 + 0.3 * min(1.0, best_sim / 0.85)
        adjusted = best_base_score * score_scale

        # Active-exploitation boost (attack_vector only, but generic)
        boost_phrases = settings.get("active_exploitation_phrases", [])
        boost_val = settings.get("active_exploitation_boost", 0)
        if boost_phrases and boost_val:
            if any(p in text.lower() for p in boost_phrases):
                adjusted = min(1.0, adjusted + boost_val)

        evidence = {
            "source": section.get("evidence_source_nlp", "NLP Extraction"),
            "matched_vector": best_name.replace("_", " "),
            "similarity": round(best_sim, 2),
            "exploitability_score": adjusted,
            "interpretation": _interpret_label(adjusted),
            "confidence": 0.9 if best_sim > 0.75 else 0.7,
            "method": "semantic_similarity",
            "features": {section["feature"]: adjusted},
        }
        return adjusted, evidence

    # ------------------------------------------------------------------
    # Internal: keyword fallback
    # ------------------------------------------------------------------

    def _extract_keywords(
        self,
        section: Dict[str, Any],
        text: str,
        settings: Dict[str, Any],
    ) -> Optional[Tuple[float, Dict[str, Any]]]:
        keywords: Dict[str, float] = section.get("keywords", {})
        mode = settings.get("mode", "")
        lowered = text.lower()

        matched: List[str] = []
        scores: List[float] = []

        for kw, score in keywords.items():
            if kw in lowered:
                matched.append(kw)
                scores.append(score)

        # Binary mode (safety keywords)
        if mode == "binary":
            if matched:
                return 1.0, {
                    "source": section.get("evidence_source_kw", "Keyword Extraction"),
                    "matched_keywords": matched[:5],
                    "features": {section["feature"]: 1.0},
                }
            return None

        if not matched:
            return None

        # Multi-match scoring
        multi_mode = settings.get("multi_match_mode", "max")
        if multi_mode == "avg_top_2" and len(scores) >= 2:
            top = sorted(scores, reverse=True)[:2]
            final = sum(top) / len(top)
        elif multi_mode == "avg_top_3" and len(scores) >= 3:
            top = sorted(scores, reverse=True)[:3]
            final = sum(top) / len(top)
        else:
            final = max(scores)

        final = _clamp(final)

        # Multi-keyword boost
        min_count = settings.get("multi_keyword_min_count", 999)
        boost = settings.get("multi_keyword_boost", 0)
        if boost and len(matched) >= min_count and final < 0.9:
            final = _clamp(final + boost)

        # Combo boosts (data_sensitivity)
        combo_boost = settings.get("combo_boost", 0)
        for combo in section.get("combos", []):
            if all(w in lowered for w in combo):
                final = _clamp(final + combo_boost)

        # Active-exploitation boost (attack_vector keywords)
        boost_phrases = settings.get("active_exploitation_phrases", [])
        boost_val = settings.get("active_exploitation_boost", 0)
        if boost_phrases and boost_val:
            if any(p in lowered for p in boost_phrases):
                final = _clamp(final + boost_val)

        # Business impact boost (impact_scope)
        biz_phrases = section.get("business_impact_phrases", [])
        biz_boost = settings.get("business_impact_boost", 0)
        if biz_phrases and biz_boost:
            if any(p in lowered for p in biz_phrases):
                final = _clamp(final + biz_boost)

        # Numerical system count (impact_scope keywords)
        numbers_pattern = r'\b(\d+)\s+(systems?|servers?|machines?|hosts?|devices?)\b'
        num_match = re.search(numbers_pattern, lowered)
        if num_match:
            count = int(num_match.group(1))
            num_score = self._count_to_score(section, count)
            final = max(final, num_score)

        evidence = {
            "source": section.get("evidence_source_kw", "Keyword Extraction"),
            "matched_keywords": matched[:5],
            "score": final,
            "interpretation": _interpret_label(final),
            "confidence": 0.9 if len(matched) >= 2 else (0.8 if matched else 0.3),
            "method": "keyword_matching",
            "features": {section["feature"]: final},
        }
        return final, evidence

    # ------------------------------------------------------------------
    # Internal: dependency parse patterns
    # ------------------------------------------------------------------

    def _check_dependency_patterns(
        self,
        section: Dict[str, Any],
        text: str,
        *,
        doc: Any = None,
    ) -> Optional[Tuple[float, Dict[str, Any]]]:
        patterns = section.get("dependency_patterns", {})
        if not patterns or self._nlp is None:
            return None

        if doc is None:
            doc = self._nlp(text.lower())
        for pname, pdef in patterns.items():
            verbs = pdef.get("verbs", [])
            objects = pdef.get("objects", [])
            dep_score = pdef.get("score", 0.85)
            for token in doc:
                if token.lemma_ in verbs:
                    subtree_text = " ".join(t.text for t in token.subtree)
                    if any(obj in subtree_text for obj in objects):
                        return dep_score, {
                            "source": section.get("evidence_source_nlp", "NLP Extraction"),
                            "method": "dependency_pattern",
                            "pattern": pname,
                            "matched_verb": token.text,
                            "confidence": 0.95,
                        }
        return None

    # ------------------------------------------------------------------
    # Internal: prevention short-circuit
    # ------------------------------------------------------------------

    def _check_prevention(
        self,
        section: Dict[str, Any],
        text: str,
        *,
        doc: Any = None,
    ) -> Optional[Tuple[float, Dict[str, Any]]]:
        prev_patterns = section.get("prevention_patterns", [])
        threat_kws = section.get("prevention_threat_keywords", [])
        prev_score = section.get("prevention_score", 0.2)

        lowered = text.lower()
        if any(p in lowered for p in prev_patterns):
            if any(kw in lowered for kw in threat_kws):
                return prev_score, {
                    "source": section.get("evidence_source_nlp", "NLP Extraction"),
                    "method": "prevention_detected",
                    "note": "Threat was prevented/mitigated",
                    "confidence": 0.95,
                }

        # Also check negations via spaCy dependency parse
        if self._nlp is not None:
            if doc is None:
                doc = self._nlp(lowered)
            negated_keywords = ["breach", "attack", "compromise", "exploit", "occur", "happen"]
            for token in doc:
                if token.dep_ == "neg":
                    head = token.head
                    if any(kw in head.lemma_ for kw in negated_keywords):
                        return prev_score, {
                            "source": section.get("evidence_source_nlp", "NLP Extraction"),
                            "method": "negation_detected",
                            "negated_term": head.text,
                            "confidence": 0.9,
                        }
        return None

    # ------------------------------------------------------------------
    # Internal: helpers
    # ------------------------------------------------------------------

    def _count_to_score(self, section: Dict[str, Any], count: int) -> float:
        """Map a numerical system count to a scope score using taxonomy tiers."""
        tiers = section.get("system_count_tiers", [])
        for tier in tiers:
            if count >= tier["min_count"]:
                return tier["score"]
        return 0.5  # ultimate fallback
