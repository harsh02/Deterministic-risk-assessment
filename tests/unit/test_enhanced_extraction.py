#!/usr/bin/env python3
"""
Test enhanced semantic extraction with sophisticated patterns
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

print("=" * 70)
print("ENHANCED SEMANTIC EXTRACTION TEST")
print("=" * 70)

cfg = risk_engine.load_config(str(DEFAULT_CONFIG_PATH))

test_cases = [
    {
        "name": "Zero-day RCE with detailed context",
        "input": {
            "title": "Zero-day remote code execution vulnerability",
            "description": "Critical zero-day RCE discovered in authentication service. Allows attackers to execute arbitrary code with system privileges. Affects 50 production servers containing customer credit card data and patient medical records. Operations down for 3 days. Revenue impact estimated at $500k per day.",
        },
    },
    {
        "name": "Ransomware with multiple data types",
        "input": {
            "title": "Novel ransomware variant encrypted enterprise systems",
            "description": "New ransomware strain encrypted all production and backup servers. Encrypted data includes customer financial information, employee SSNs, proprietary source code, and trade secrets. Attackers demanding $5M ransom.",
        },
    },
    {
        "name": "DDoS with business impact",
        "input": {
            "title": "Massive DDoS attack causing widespread service disruption",
            "description": "Distributed denial of service attack targeting customer-facing APIs. All services unavailable. Affecting all customers globally. Business operations completely halted.",
        },
    },
    {
        "name": "Data breach with scope indicators",
        "input": {
            "title": "Unauthorized access to production database",
            "description": "Attacker gained access to 10 database servers containing customer PII, payment tokens, and authentication credentials. Data exfiltration confirmed across multiple systems. Estimated 100k user accounts compromised.",
        },
    },
    {
        "name": "Supply chain attack",
        "input": {
            "title": "Supply chain compromise affecting internal infrastructure",
            "description": "Third-party library backdoor discovered. Code injection vulnerability allows remote code execution. Affects entire organization's infrastructure including critical production systems with customer financial data.",
        },
    },
]

for i, test in enumerate(test_cases, 1):
    print(f"\n{'='*70}")
    print(f"TEST {i}: {test['name']}")
    print(f"{'='*70}")

    # Build features
    features, metadata = risk_engine.build_features(cfg, {}, test["input"])

    # Compute scores
    scores = risk_engine.compute_scores(cfg, features, {})

    print("\n📋 Input:")
    print(f"  {test['input']['title'][:60]}...")

    print("\n📊 SCORES:")
    print(f"  Likelihood:  {scores['likelihood']*10:.1f}/10")
    print(f"  Severity:    {scores['severity']*10:.1f}/10")
    print(f"  Risk:        {scores['overall_risk']}")
    print(f"  Mode:        {scores.get('severity_mode', 'unknown').upper()}")

    print("\n🔍 EXTRACTED FEATURES:")
    print(f"  Impact Category:   {features.get('Impact_Category', 0)*100:.0f}%")
    print(f"  Data Sensitivity:  {features.get('Data_Sensitivity', 0)*100:.0f}%")
    print(f"  Impact Scope:      {features.get('Impact_Scope', 0)*100:.0f}%")

    print("\n📝 EVIDENCE:")
    for ev in metadata.get("evidence", []):
        if ev.get("source") == "Impact Category Extraction":
            print(f"  Impact: {ev.get('matched_category', 'none')}")
            if ev.get("all_matches"):
                print(f"    Matches: {', '.join(ev['all_matches'][:3])}")
        elif ev.get("source") == "Data Sensitivity Extraction":
            print(f"  Sensitivity: {ev.get('sensitivity_level', 'none')}")
            if ev.get("matched_keywords"):
                print(f"    Keywords: {', '.join(ev['matched_keywords'][:5])}")
        elif ev.get("source") == "Impact Scope Extraction":
            print(f"  Scope: {ev.get('matched_scope', 'none')}")
            if ev.get("all_matches"):
                print(f"    Matches: {', '.join(ev['all_matches'])}")

    print(f"\n  Confidence: {metadata.get('confidence', 0)*100:.0f}%")

print(f"\n{'='*70}")
print("ENHANCEMENT SUMMARY")
print("=" * 70)
print("""
✅ Enhanced Semantic Extraction Features:

1. IMPACT CATEGORY (Expanded from 8 to 30+ keywords)
   • RCE patterns: "remote code execution", "rce", "arbitrary code"
   • Ransomware: "encrypted", "crypto locker", "file encryption"
   • Service disruption: "operations down", "system failure", "ddos"
   • Data issues: "data breach", "exfiltration", "corrupted"
   • Zero-day boost: "zero-day", "novel attack"

2. DATA SENSITIVITY (Expanded from 12 to 40+ keywords)
   • Financial: "credit card", "cvv", "bank account", "transaction"
   • Healthcare: "patient", "medical", "phi", "health record"
   • Credentials: "password", "api key", "encryption key", "certificate"
   • Business: "proprietary", "trade secret", "source code"
   • PII: "ssn", "passport", "driver license"
   • Combo boosting: "customer + financial" = extra boost

3. IMPACT SCOPE (Enhanced with numerical detection)
   • Detects: "50 servers" → High scope (0.9)
   • Detects: "all customers" → Maximum scope (1.0)
   • Business impact keywords boost score
   • Regex patterns for system counts

4. SMARTER DEFAULTS
   • Attack_Frequency: 0.35 → 0.4 (better zero-day handling)
   • Impact_Category: 0.5 → 0.6 (conservative but realistic)
   • Data_Sensitivity: 0.5 → 0.6 (assume sensitive until proven otherwise)

5. CONFIDENCE SCORING
   • Multiple keyword matches = higher confidence
   • 0.9 = Multiple matches detected
   • 0.8 = Single strong match
   • 0.3 = Using defaults
""")
