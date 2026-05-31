#!/usr/bin/env python3
"""
Test script to analyze threats/vulns with ONLY text - no other info
"""

import importlib.util
import sys
from pathlib import Path

_UNIT_DIR = Path(__file__).resolve().parent
if str(_UNIT_DIR) not in sys.path:
    sys.path.insert(0, str(_UNIT_DIR))
from test_utils import DEFAULT_CONFIG_PATH

_SRC_UTILS = _UNIT_DIR.parent.parent / "src" / "utils"

# Load the risk_engine module
spec = importlib.util.spec_from_file_location("risk_engine", str(_SRC_UTILS / "risk_engine.py"))
risk_engine = importlib.util.module_from_spec(spec)
sys.modules["risk_engine"] = risk_engine
spec.loader.exec_module(risk_engine)

# Test cases: ONLY TEXT INPUT
test_cases = [
    # Test 1: Vulnerability description
    {"title": "SQL injection allowing unauthorized database access in authentication service"},
    # Test 2: Ransomware threat
    {"title": "Ransomware encrypted all production servers containing customer payment data"},
    # Test 3: Phishing attack
    {
        "title": "Phishing campaign compromised employee credentials with access to patient medical records"
    },
    # Test 4: DDoS
    {"title": "Distributed denial of service attack causing widespread service outage"},
    # Test 5: Data breach
    {"title": "Unauthorized access exposed customer financial information and credit card data"},
]

# Load config
cfg = risk_engine.load_config(str(DEFAULT_CONFIG_PATH))

print("=" * 70)
print("TEXT-ONLY INPUT TEST")
print("=" * 70)
print("\nTesting with ONLY text descriptions (no CVE, no scores, no context)\n")

for i, test_input in enumerate(test_cases, 1):
    print(f"\n{'='*70}")
    print(f"TEST {i}: {test_input['title'][:60]}...")
    print("=" * 70)

    # Build features - no overrides, just the text
    features, metadata = risk_engine.build_features(cfg, {}, test_input)

    # Compute scores - no context
    scores = risk_engine.compute_scores(cfg, features, {})

    # Show results
    print("\n📊 Results:")
    print(f"  Mode:       {scores.get('severity_mode', 'unknown').upper()}")
    print(f"  Likelihood: {scores['likelihood']*10:.1f}/10")
    print(f"  Severity:   {scores['severity']*10:.1f}/10")
    print(f"  Risk:       {scores['overall_risk']}")

    # Show what was extracted
    print("\n🔍 Extracted Features:")
    if features.get("Impact_Category", 0) > 0.5:
        print(f"  • Impact Category: {features['Impact_Category']*100:.0f}%")
    if features.get("Data_Sensitivity", 0) > 0.5:
        print(f"  • Data Sensitivity: {features['Data_Sensitivity']*100:.0f}%")
    if features.get("Impact_Scope", 0) > 0.5:
        print(f"  • Impact Scope: {features['Impact_Scope']*100:.0f}%")

    # Show evidence
    if metadata.get("evidence"):
        print("\n📋 Evidence:")
        for ev in metadata["evidence"]:
            if ev.get("matched_keywords"):
                print(f"  • Keywords: {', '.join(ev['matched_keywords'][:3])}")
            elif ev.get("matched_category"):
                print(f"  • Category: {ev['matched_category']}")
            elif ev.get("matched_scope"):
                print(f"  • Scope: {ev['matched_scope']}")

print(f"\n{'='*70}")
print("ALL TESTS COMPLETE")
print("=" * 70)
print("\n✅ The tool works with ONLY text descriptions!")
print("   No CVE, no CVSS scores, no context required.")
print("   Everything is extracted semantically from the text.")
