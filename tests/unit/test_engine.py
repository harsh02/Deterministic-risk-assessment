"""Pytest-compatible smoke tests for the DetRisk risk engine.

Validates core pipeline functionality: config loading, feature assembly,
score computation, and evidence provenance.
"""

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

# ---------------------------------------------------------------------------
# Bootstrap: resolve paths from this file so tests work regardless of cwd
# ---------------------------------------------------------------------------
_UNIT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _UNIT_DIR.parent.parent
_SRC_UTILS = _PROJECT_ROOT / "src" / "utils"
_CONFIG_PATH = _PROJECT_ROOT / "policy" / "risk_rules.hybrid.yaml"

if str(_SRC_UTILS) not in sys.path:
    sys.path.insert(0, str(_SRC_UTILS))

# Import the risk engine using spec loader to mirror existing pattern
spec = importlib.util.spec_from_file_location("risk_engine", str(_SRC_UTILS / "risk_engine.py"))
risk_engine = importlib.util.module_from_spec(spec)
sys.modules["risk_engine"] = risk_engine
spec.loader.exec_module(risk_engine)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def cfg():
    """Load risk policy config once for the entire test session."""
    return risk_engine.load_config(str(_CONFIG_PATH))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestConfigLoading:
    def test_config_loads_without_error(self, cfg):
        assert cfg is not None
        assert isinstance(cfg, dict)

    def test_config_has_meta(self, cfg):
        assert "meta" in cfg
        assert "version" in cfg["meta"]

    def test_config_has_scoring(self, cfg):
        assert "scoring" in cfg


class TestFeatureAssembly:
    def test_build_features_returns_tuple(self, cfg):
        payload = {"title": "Test threat", "description": "A test vulnerability."}
        result = risk_engine.build_features(cfg, overrides={}, input_payload=payload)
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_build_features_returns_dict_and_metadata(self, cfg):
        payload = {"title": "Test threat", "description": "A test vulnerability."}
        features, metadata = risk_engine.build_features(cfg, overrides={}, input_payload=payload)
        assert isinstance(features, dict)
        assert isinstance(metadata, dict)

    def test_features_are_floats(self, cfg):
        payload = {
            "title": "SQL injection in payment gateway",
            "description": "Unauthenticated SQL injection allows credit card data extraction.",
        }
        features, _ = risk_engine.build_features(cfg, overrides={}, input_payload=payload)
        for key, value in features.items():
            assert isinstance(value, (int, float)), f"Feature {key} is {type(value)}, expected numeric"

    def test_overrides_applied(self, cfg):
        payload = {"title": "Test", "description": "Test"}
        overrides = {"CVSS_BaseScore": 9.5}
        features, _ = risk_engine.build_features(cfg, overrides=overrides, input_payload=payload)
        assert features.get("CVSS_BaseScore") == 9.5


class TestScoreComputation:
    def test_compute_scores_returns_dict(self, cfg):
        payload = {
            "title": "Remote code execution via deserialization",
            "description": "Unauthenticated RCE through Java deserialization in public API.",
        }
        features, _ = risk_engine.build_features(cfg, overrides={}, input_payload=payload)
        scores = risk_engine.compute_scores(cfg, features, {})
        assert isinstance(scores, dict)

    def test_scores_have_required_keys(self, cfg):
        payload = {
            "title": "Privilege escalation in kernel driver",
            "description": "Local attacker can escalate to root via buffer overflow.",
        }
        features, _ = risk_engine.build_features(cfg, overrides={}, input_payload=payload)
        scores = risk_engine.compute_scores(cfg, features, {})
        assert "likelihood" in scores
        assert "severity" in scores
        assert "overall_risk" in scores

    def test_scores_in_valid_range(self, cfg):
        payload = {
            "title": "XSS in admin panel",
            "description": "Reflected cross-site scripting in administration interface.",
        }
        features, _ = risk_engine.build_features(cfg, overrides={}, input_payload=payload)
        scores = risk_engine.compute_scores(cfg, features, {})
        assert 0.0 <= scores["likelihood"] <= 1.0
        assert 0.0 <= scores["severity"] <= 1.0

    def test_overall_risk_is_valid_label(self, cfg):
        payload = {"title": "Test", "description": "Minor informational finding."}
        features, _ = risk_engine.build_features(cfg, overrides={}, input_payload=payload)
        scores = risk_engine.compute_scores(cfg, features, {})
        valid_labels = {"Critical", "High", "Medium", "Low", "Informational"}
        assert scores["overall_risk"] in valid_labels


class TestEvidenceProvenance:
    def test_evidence_list_populated(self, cfg):
        payload = {
            "title": "SQL injection in login form",
            "description": "Authentication bypass via SQL injection allowing full database access.",
        }
        _, metadata = risk_engine.build_features(cfg, overrides={}, input_payload=payload)
        evidence = metadata.get("evidence", [])
        assert isinstance(evidence, list)
        assert len(evidence) > 0, "Expected at least one evidence record"

    def test_evidence_has_source(self, cfg):
        payload = {
            "title": "Ransomware encrypted production servers",
            "description": "Ransomware encrypted all production servers with customer data.",
        }
        _, metadata = risk_engine.build_features(cfg, overrides={}, input_payload=payload)
        for ev in metadata.get("evidence", []):
            assert "source" in ev, f"Evidence record missing 'source': {ev}"


class TestSeverityModes:
    def test_without_cvss_mode(self, cfg):
        """Text-only input (no CVE) should use without_cvss severity mode."""
        payload = {
            "title": "Phishing campaign targeting employees",
            "description": "Spear phishing emails with credential harvesting landing pages.",
        }
        features, _ = risk_engine.build_features(cfg, overrides={}, input_payload=payload)
        scores = risk_engine.compute_scores(cfg, features, {})
        assert scores.get("severity_mode") == "without_cvss"

    def test_with_cvss_mode(self, cfg):
        """Input with CVSS override should use with_cvss severity mode."""
        payload = {"title": "Test CVE", "description": "Test vuln with CVSS."}
        overrides = {"CVSS_BaseScore": 7.5, "CVSS_Exploitability": 2.8}
        features, _ = risk_engine.build_features(cfg, overrides=overrides, input_payload=payload)
        scores = risk_engine.compute_scores(cfg, features, {})
        assert scores.get("severity_mode") == "with_cvss"


class TestSafeFormulaEvaluator:
    def test_basic_arithmetic(self):
        evaluator = risk_engine.SafeFormulaEvaluator({"x": 2.0, "y": 3.0})
        assert evaluator.evaluate("x + y") == 5.0

    def test_clamp_via_min_max(self):
        evaluator = risk_engine.SafeFormulaEvaluator({"x": 1.5})
        result = evaluator.evaluate("min(max(x, 0), 1)")
        assert result == 1.0

    def test_rejects_dangerous_code(self):
        evaluator = risk_engine.SafeFormulaEvaluator({})
        with pytest.raises(ValueError):
            evaluator.evaluate("__import__('os').system('echo pwned')")
