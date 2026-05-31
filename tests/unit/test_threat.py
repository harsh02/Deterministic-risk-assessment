#!/usr/bin/env python3
"""
Quick test script to analyze a specific threat
"""

import importlib.util
import json
import sys
from pathlib import Path

try:
    from .test_utils import DEFAULT_CONFIG_PATH, PROJECT_ROOT
except ImportError:
    # Allow running as a standalone script via `python tests/unit/test_threat.py`
    CURRENT_DIR = Path(__file__).resolve().parent
    if str(CURRENT_DIR) not in sys.path:
        sys.path.insert(0, str(CURRENT_DIR))
    from test_utils import DEFAULT_CONFIG_PATH, PROJECT_ROOT

SRC_UTILS = PROJECT_ROOT / "src" / "utils"
if str(SRC_UTILS) not in sys.path:
    sys.path.insert(0, str(SRC_UTILS))

# Load the risk_engine module
spec = importlib.util.spec_from_file_location("risk_engine", str(SRC_UTILS / "risk_engine.py"))
risk_engine = importlib.util.module_from_spec(spec)
sys.modules["risk_engine"] = risk_engine
spec.loader.exec_module(risk_engine)

# Test threat: SQL Injection with safety implications
threat_input = {
    "title": "SQL injection in payment gateway",
    "description": "SQL injection vulnerability discovered in payment processing gateway that handles credit card transactions. Attacker could extract customer payment data including credit card numbers, CVV codes, and personal information.",
    "feature_overrides": {
        "CVSS_BaseScore": 9.1,
        "CVSS_Exploitability": 3.9,
        "KnownExploited": 1,
        "Attack_Frequency": 0.8,
        "System_Maturity": 0.4,
        "Safety_Impact_Flag": 0,
    },
    "context": {"asset_type": "BackendService", "criticality": 0.9},
}

print("=" * 70)
print("THREAT ANALYSIS TEST")
print("=" * 70)
print("\n📋 Input Threat:")
print(json.dumps(threat_input, indent=2))

# Load config
cfg = risk_engine.load_config(str(DEFAULT_CONFIG_PATH))

# Build features (pass overrides separately and full input for DB resolution)
features = risk_engine.build_features(cfg, threat_input.get("feature_overrides", {}), threat_input)

print("\n\n🔍 Extracted Features:")
print(json.dumps(features, indent=2))

# Compute risk scores
scores = risk_engine.compute_scores(cfg, features[0], threat_input.get("context", {}))

# Get feature values for calculation breakdown
f = scores["feature_breakdown"]

# Convert to 1-10 scale
likelihood_score = round(scores["likelihood"] * 10, 1)
severity_score = round(scores["severity"] * 10, 1)
overall_score = round((scores["likelihood"] * scores["severity"]) * 100, 1)

print("\n\n" + "=" * 70)
print("📊 RISK SCORE ANALYSIS")
print("=" * 70)

# Likelihood Calculation with Reasoning
print(
    "\n🎯 LIKELIHOOD OF ATTACK (LoA): {}/10 ({:.3f})".format(likelihood_score, scores["likelihood"])
)
print("-" * 70)
print("Formula: 35% × Exploitability + 35% × Known Exploited + 20% × Attack Frequency + 10% × EPSS")
print()

exploit_norm = f["CVSS_Exploitability"] / 10.0
exploit_contribution = 0.35 * exploit_norm
known_contribution = 0.35 * f["KnownExploited"]
attack_contribution = 0.20 * f["Attack_Frequency"]
epss_contribution = 0.10 * f["EPSS_Score"]

print(
    f"  ├─ 35% × Exploitability:     0.35 × {f['CVSS_Exploitability']:.1f}/10 = {exploit_contribution:.3f}"
)
print(f"  │  └─ Rationale: CVSS Exploitability is {f['CVSS_Exploitability']:.1f}/10 (Very High)")
print("  │     Easy to exploit with minimal skill required")
print()
print(
    f"  ├─ 35% × Known Exploited:    0.35 × {f['KnownExploited']:.0f}    = {known_contribution:.3f}"
)
print(
    f"  │  └─ Rationale: {'Active exploitation in the wild' if f['KnownExploited'] == 1 else 'No known exploitation'}"
)
print(
    f"  │     {'Attackers have working exploits available' if f['KnownExploited'] == 1 else 'Theoretical threat only'}"
)
print()
print(
    f"  ├─ 20% × Attack Frequency:   0.20 × {f['Attack_Frequency']:.2f}  = {attack_contribution:.3f}"
)
print(f"  │  └─ Rationale: Attack pattern frequency is {f['Attack_Frequency']*100:.0f}%")
print(
    f"  │     {'Very common attack vector' if f['Attack_Frequency'] > 0.7 else 'Moderate frequency'}"
)
print()
print(f"  └─ 10% × EPSS Score:         0.10 × {f['EPSS_Score']:.2f}  = {epss_contribution:.3f}")
print(f"     └─ Rationale: Exploit Prediction Score is {f['EPSS_Score']*100:.1f}%")
print("        Probability this vulnerability will be exploited in the wild")
print()
print(
    f"  TOTAL: {exploit_contribution:.3f} + {known_contribution:.3f} + {attack_contribution:.3f} + {epss_contribution:.3f} = {scores['likelihood']:.3f}"
)
print()
print("  ℹ️  Note: Exploitability & Known Exploited have equal weight (35% each)")
print("           System Maturity removed (subjective, requires user documentation)")

# Severity Calculation with Reasoning
print("\n⚠️  SEVERITY SCORE: {}/10 ({:.3f})".format(severity_score, scores["severity"]))
print("-" * 70)
print(f"Severity Mode: {scores.get('severity_mode', 'unknown').upper()}")
print()

if scores.get("severity_mode") == "with_cvss":
    # Vulnerability path (has CVSS)
    print("Formula: 70% × CVSS Base + 20% × Asset Criticality + 10% × Impact Scope")
    print()

    cvss_norm = f["CVSS_BaseScore"] / 10.0
    cvss_contribution = 0.70 * cvss_norm
    criticality_contribution = 0.20 * scores["context_criticality"]
    scope_contribution = 0.10 * f.get("Impact_Scope", 0.5)

    print(
        f"  ├─ 70% × CVSS Base Score:    0.70 × {f['CVSS_BaseScore']:.1f}/10 = {cvss_contribution:.3f}"
    )
    print(f"  │  └─ Rationale: CVSS Base Score is {f['CVSS_BaseScore']:.1f}/10")
    if f["CVSS_BaseScore"] >= 9.0:
        print("  │     CRITICAL vulnerability with severe impact")
    elif f["CVSS_BaseScore"] >= 7.0:
        print("  │     HIGH severity vulnerability")
    else:
        print("  │     MEDIUM severity vulnerability")
    print()
    print(
        f"  ├─ 20% × Asset Criticality:  0.20 × {scores['context_criticality']:.1f}   = {criticality_contribution:.3f}"
    )
    print(
        f"  │  └─ Rationale: Asset type is '{threat_input.get('context', {}).get('asset_type', 'Unknown')}'"
    )
    print(f"  │     Business criticality: {scores['context_criticality']*100:.0f}%")
    print()
    print(
        f"  └─ 10% × Impact Scope:       0.10 × {f.get('Impact_Scope', 0.5):.2f}  = {scope_contribution:.3f}"
    )
    print(f"     └─ Rationale: Impact scope is {f.get('Impact_Scope', 0.5)*100:.0f}%")
    print(f"        {'Widespread impact' if f.get('Impact_Scope', 0.5) > 0.7 else 'Limited scope'}")
    print()
    print(
        f"  TOTAL: {cvss_contribution:.3f} + {criticality_contribution:.3f} + {scope_contribution:.3f} = {scores['severity']:.3f}"
    )
else:
    # Threat path (no CVSS)
    print("Formula: 50% × Impact Category + 30% × Asset Criticality + 20% × Data Sensitivity")
    print()

    impact_contribution = 0.50 * f.get("Impact_Category", 0.5)
    criticality_contribution = 0.30 * scores["context_criticality"]
    sensitivity_contribution = 0.20 * f.get("Data_Sensitivity", 0.5)

    print(
        f"  ├─ 50% × Impact Category:    0.50 × {f.get('Impact_Category', 0.5):.2f}  = {impact_contribution:.3f}"
    )
    print(f"  │  └─ Rationale: Impact category score is {f.get('Impact_Category', 0.5)*100:.0f}%")
    impact_val = f.get("Impact_Category", 0.5)
    if impact_val >= 0.9:
        print("  │     Data destruction or ransomware-level impact")
    elif impact_val >= 0.7:
        print("  │     Service disruption or data manipulation")
    else:
        print("  │     Moderate impact level")
    print()
    print(
        f"  ├─ 30% × Asset Criticality:  0.30 × {scores['context_criticality']:.1f}   = {criticality_contribution:.3f}"
    )
    print(
        f"  │  └─ Rationale: Asset type is '{threat_input.get('context', {}).get('asset_type', 'Unknown')}'"
    )
    print(f"  │     Business criticality: {scores['context_criticality']*100:.0f}%")
    print()
    print(
        f"  └─ 20% × Data Sensitivity:   0.20 × {f.get('Data_Sensitivity', 0.5):.2f}  = {sensitivity_contribution:.3f}"
    )
    print(f"     └─ Rationale: Data sensitivity is {f.get('Data_Sensitivity', 0.5)*100:.0f}%")
    sens_val = f.get("Data_Sensitivity", 0.5)
    if sens_val >= 0.9:
        print("        Financial/healthcare/PII data at risk")
    elif sens_val >= 0.7:
        print("        Credentials or proprietary data at risk")
    else:
        print("        General data sensitivity")
    print()
    print(
        f"  TOTAL: {impact_contribution:.3f} + {criticality_contribution:.3f} + {sensitivity_contribution:.3f} = {scores['severity']:.3f}"
    )

# Overall Risk Matrix
print("\n🎲 OVERALL RISK CLASSIFICATION: {}".format(scores["overall_risk"]))
print("-" * 70)
print("5×5 Risk Matrix:")
print(f"  Likelihood: {scores['likelihood']:.3f} → Bin: {int(scores['likelihood'] / 0.2) + 1}/5")
print(f"  Severity:   {scores['severity']:.3f} → Bin: {int(scores['severity'] / 0.2) + 1}/5")
print()
print("Matrix lookup gives: {}".format(scores["overall_risk"]))
print()
if scores["overall_risk"] == "Critical":
    print("  ⚠️  CRITICAL: Immediate action required")
    print("     • Escalate to security leadership")
    print("     • Deploy emergency patches/mitigations")
    print("     • Monitor for active exploitation")
elif scores["overall_risk"] == "High":
    print("  ⚠️  HIGH: Priority remediation needed")
elif scores["overall_risk"] == "Medium":
    print("  ⚙️  MEDIUM: Plan remediation within SLA")
else:
    print("  ✓  LOW: Monitor and patch in normal cycle")

print("\n" + "=" * 70)
print("ANALYSIS COMPLETE")
print("=" * 70)
