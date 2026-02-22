#!/usr/bin/env python3
"""
Test script to analyze a THREAT (no CVE/CVSS) using semantic extraction
"""
import json
import importlib.util
import sys
from pathlib import Path

_UNIT_DIR = Path(__file__).resolve().parent
_SRC_UTILS = _UNIT_DIR.parent.parent / "src" / "utils"

# Load the risk_engine module
spec = importlib.util.spec_from_file_location("risk_engine", str(_SRC_UTILS / "risk_engine.py"))
risk_engine = importlib.util.module_from_spec(spec)
sys.modules["risk_engine"] = risk_engine
spec.loader.exec_module(risk_engine)

# Test threat: Ransomware attack (no CVE)
threat_input = {
    "title": "Ransomware attack encrypted production servers",
    "description": "Ransomware encrypted all production servers containing customer financial data and proprietary source code. Operations down for 3 days affecting multiple systems across the enterprise. Attackers demanding payment for decryption keys.",
    "context": {
        "asset_type": "BackendService",
        "criticality": 0.9
    }
}

print("="*70)
print("THREAT ANALYSIS TEST (NO CVE)")
print("="*70)
print("\n📋 Input Threat:")
print(json.dumps(threat_input, indent=2))

# Load config
_PROJECT_ROOT = _UNIT_DIR.parent.parent
cfg = risk_engine.load_config(str(_PROJECT_ROOT / "policy" / "risk_rules.hybrid.yaml"))

# Build features (pass overrides separately and full input for DB resolution)
features = risk_engine.build_features(
    cfg, 
    threat_input.get("feature_overrides", {}),
    threat_input
)

print("\n\n🔍 Extracted Features:")
print(json.dumps(features[0], indent=2))
print("\n📊 Evidence:")
for ev in features[1].get("evidence", []):
    print(f"  • {ev.get('source')}: {ev}")

# Get feature values for calculation breakdown
f = features[0]

# Compute risk scores
scores = risk_engine.compute_scores(cfg, features[0], threat_input.get("context", {}))

# Convert to 1-10 scale
likelihood_score = round(scores["likelihood"] * 10, 1)
severity_score = round(scores["severity"] * 10, 1)
overall_score = round((scores["likelihood"] * scores["severity"]) * 100, 1)

print("\n\n" + "="*70)
print("📊 RISK SCORE ANALYSIS")
print("="*70)

# Likelihood
print("\n🎯 LIKELIHOOD OF ATTACK (LoA): {}/10 ({:.3f})".format(likelihood_score, scores['likelihood']))
print("-" * 70)
print("Formula: 35% × Exploitability + 35% × Known Exploited + 20% × Attack Frequency + 10% × EPSS")
print()

exploit_norm = f["CVSS_Exploitability"] / 10.0
exploit_contribution = 0.35 * exploit_norm
known_contribution = 0.35 * f["KnownExploited"]
attack_contribution = 0.20 * f["Attack_Frequency"]
epss_contribution = 0.10 * f["EPSS_Score"]

print(f"  ├─ 35% × Exploitability:     0.35 × {f['CVSS_Exploitability']:.1f}/10 = {exploit_contribution:.3f}")
print(f"  ├─ 35% × Known Exploited:    0.35 × {f['KnownExploited']:.0f}    = {known_contribution:.3f}")
print(f"  ├─ 20% × Attack Frequency:   0.20 × {f['Attack_Frequency']:.2f}  = {attack_contribution:.3f}")
print(f"  └─ 10% × EPSS Score:         0.10 × {f['EPSS_Score']:.2f}  = {epss_contribution:.3f}")
print(f"\n  TOTAL: {scores['likelihood']:.3f}")

# Severity
print("\n⚠️  SEVERITY SCORE: {}/10 ({:.3f})".format(severity_score, scores['severity']))
print("-" * 70)
print(f"Severity Mode: {scores.get('severity_mode', 'unknown').upper()}")
print()

if scores.get('severity_mode') == 'with_cvss':
    print("Formula: 70% × CVSS Base + 20% × Asset Criticality + 10% × Impact Scope")
    cvss_contribution = 0.70 * (f["CVSS_BaseScore"] / 10.0)
    criticality_contribution = 0.20 * scores["context_criticality"]
    scope_contribution = 0.10 * f.get("Impact_Scope", 0.5)
    print(f"  ├─ 70% × CVSS Base:    {cvss_contribution:.3f}")
    print(f"  ├─ 20% × Criticality:  {criticality_contribution:.3f}")
    print(f"  └─ 10% × Scope:        {scope_contribution:.3f}")
else:
    print("Formula: 50% × Impact Category + 30% × Asset Criticality + 20% × Data Sensitivity")
    print()
    
    impact_contribution = 0.50 * f.get("Impact_Category", 0.5)
    criticality_contribution = 0.30 * scores["context_criticality"]
    sensitivity_contribution = 0.20 * f.get("Data_Sensitivity", 0.5)
    
    print(f"  ├─ 50% × Impact Category:    0.50 × {f.get('Impact_Category', 0.5):.2f}  = {impact_contribution:.3f}")
    print(f"  │  └─ Impact: ", end="")
    if f.get('Impact_Category', 0.5) >= 0.9:
        print("RANSOMWARE/DATA DESTRUCTION (Critical)")
    elif f.get('Impact_Category', 0.5) >= 0.7:
        print("Service disruption or data manipulation")
    else:
        print("Moderate impact")
    print()
    
    print(f"  ├─ 30% × Asset Criticality:  0.30 × {scores['context_criticality']:.1f}   = {criticality_contribution:.3f}")
    print(f"  │  └─ Asset: {threat_input.get('context', {}).get('asset_type', 'Unknown')}")
    print(f"  │     Criticality: {scores['context_criticality']*100:.0f}%")
    print()
    
    print(f"  └─ 20% × Data Sensitivity:   0.20 × {f.get('Data_Sensitivity', 0.5):.2f}  = {sensitivity_contribution:.3f}")
    print(f"     └─ Data: ", end="")
    if f.get('Data_Sensitivity', 0.5) >= 0.9:
        print("FINANCIAL/PII (High sensitivity)")
    elif f.get('Data_Sensitivity', 0.5) >= 0.7:
        print("Credentials/proprietary data")
    else:
        print("General data")
    print()
    
    print(f"  TOTAL: {impact_contribution:.3f} + {criticality_contribution:.3f} + {sensitivity_contribution:.3f} = {scores['severity']:.3f}")

# Overall Risk
print("\n🎲 OVERALL RISK CLASSIFICATION: {}".format(scores['overall_risk']))
print("-" * 70)
print(f"  Likelihood: {scores['likelihood']:.3f} ({likelihood_score}/10)")
print(f"  Severity:   {scores['severity']:.3f} ({severity_score}/10)")
print(f"  Risk:       {scores['overall_risk']}")

if scores['overall_risk'] == 'Critical':
    print("\n  ⚠️  CRITICAL: Immediate action required!")
elif scores['overall_risk'] == 'High':
    print("\n  ⚠️  HIGH: Priority remediation needed")

print("\n" + "="*70)
print("ANALYSIS COMPLETE")
print("="*70)
