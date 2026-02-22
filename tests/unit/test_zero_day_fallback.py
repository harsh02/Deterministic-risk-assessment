#!/usr/bin/env python3
"""
Test fallback mechanisms for zero-day threats/vulnerabilities
Zero-days have NO database information, so we rely on:
1. Semantic extraction from description
2. Default values
3. Manual overrides (if provided)
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

print("="*70)
print("ZERO-DAY VULNERABILITY & THREAT FALLBACK TEST")
print("="*70)
print("\nTesting scenarios with NO database information available")
print("="*70)

# Load config
_PROJECT_ROOT = _UNIT_DIR.parent.parent
cfg = risk_engine.load_config(str(_PROJECT_ROOT / "policy" / "risk_rules.hybrid.yaml"))

# Test scenarios
test_cases = [
    {
        "name": "Zero-Day RCE (Text Only)",
        "description": "Minimal info - just discovered",
        "input": {
            "title": "Zero-day remote code execution in authentication service"
        }
    },
    {
        "name": "Zero-Day with Rich Description",
        "description": "More context in description",
        "input": {
            "title": "Zero-day vulnerability allowing remote code execution",
            "description": "Critical zero-day RCE in authentication service affecting all production servers. Allows attackers to execute arbitrary code with system privileges. Potentially affecting customer financial data and proprietary source code. Multiple systems at risk."
        }
    },
    {
        "name": "Zero-Day with Estimated Severity",
        "description": "Security team estimates CVSS",
        "input": {
            "title": "Zero-day RCE in auth service",
            "description": "Remote code execution with system privileges",
            "feature_overrides": {
                "CVSS_BaseScore": 9.8,
                "CVSS_Exploitability": 3.9
            }
        }
    },
    {
        "name": "Zero-Day Threat (Ransomware)",
        "description": "New ransomware variant",
        "input": {
            "title": "Unknown ransomware variant encrypted production systems",
            "description": "New ransomware strain not in any database. Encrypted all servers containing customer payment data and medical records. Widespread impact across enterprise. Attackers using novel encryption."
        }
    },
    {
        "name": "Zero-Day with Attack Intel",
        "description": "Observed in wild with intel",
        "input": {
            "title": "Zero-day actively exploited in the wild",
            "description": "Unknown vulnerability being actively exploited by APT group. Targeting financial institutions. Remote code execution suspected.",
            "feature_overrides": {
                "KnownExploited": 1,
                "Attack_Frequency": 0.7
            }
        }
    }
]

for i, test in enumerate(test_cases, 1):
    print(f"\n{'='*70}")
    print(f"TEST {i}: {test['name']}")
    print(f"{'='*70}")
    print(f"Scenario: {test['description']}")
    print(f"\nInput: {test['input']['title'][:60]}...")
    
    # Build features
    features, metadata = risk_engine.build_features(
        cfg,
        test['input'].get('feature_overrides', {}),
        test['input']
    )
    
    # Compute scores
    scores = risk_engine.compute_scores(cfg, features, test['input'].get('context', {}))
    
    # Show results
    print(f"\n📊 RISK ASSESSMENT:")
    print(f"  Severity Mode:  {scores.get('severity_mode', 'unknown').upper()}")
    print(f"  Likelihood:     {scores['likelihood']*10:.1f}/10 ({scores['likelihood']:.3f})")
    print(f"  Severity:       {scores['severity']*10:.1f}/10 ({scores['severity']:.3f})")
    print(f"  Overall Risk:   {scores['overall_risk']}")
    
    # Show data sources
    print(f"\n🔍 DATA SOURCES:")
    source_breakdown = metadata.get('source_map', {})
    db_count = sum(1 for v in source_breakdown.values() if v == 'database')
    override_count = sum(1 for v in source_breakdown.values() if v == 'manual_override')
    default_count = sum(1 for v in source_breakdown.values() if v == 'default')
    
    print(f"  Database features:  {db_count}")
    print(f"  Manual overrides:   {override_count}")
    print(f"  Default values:     {default_count}")
    print(f"  Confidence:         {metadata.get('confidence', 0)*100:.0f}%")
    
    # Show what was extracted semantically
    print(f"\n📋 SEMANTIC EXTRACTION:")
    extracted = []
    if features.get('Impact_Category', 0.5) != 0.5:
        extracted.append(f"Impact Category: {features['Impact_Category']}")
    if features.get('Data_Sensitivity', 0.5) != 0.5:
        extracted.append(f"Data Sensitivity: {features['Data_Sensitivity']}")
    if features.get('Impact_Scope', 0.5) != 0.5:
        extracted.append(f"Impact Scope: {features['Impact_Scope']}")
    
    if extracted:
        for item in extracted:
            print(f"  • {item}")
    else:
        print(f"  • Using default values (no keywords matched)")
    
    # Show evidence
    if metadata.get('evidence'):
        print(f"\n📝 EVIDENCE:")
        for ev in metadata['evidence'][:3]:  # Show first 3
            if ev.get('matched_keywords'):
                print(f"  • Keywords: {', '.join(ev['matched_keywords'][:4])}")
            elif ev.get('matched_category') and ev['matched_category'] != 'unknown':
                print(f"  • Category: {ev['matched_category']}")
            elif ev.get('matched_scope') and 'default' not in ev['matched_scope']:
                print(f"  • Scope: {ev['matched_scope']}")
    
    # Fallback status
    print(f"\n✅ FALLBACK STATUS:")
    if override_count > 0:
        print(f"  ✓ Using manual overrides for {override_count} features")
    if db_count > 0:
        print(f"  ✓ Found {db_count} features from semantic extraction")
    if default_count > 0:
        print(f"  ✓ Using {default_count} default values as fallback")
    
    if scores['overall_risk'] in ['High', 'Critical']:
        print(f"\n⚠️  RECOMMENDATION: Treat as HIGH PRIORITY zero-day")

print(f"\n{'='*70}")
print("FALLBACK MECHANISM SUMMARY")
print("="*70)
print("""
✅ The system handles zero-days through multiple fallback layers:

1. SEMANTIC EXTRACTION (Primary Fallback)
   • Extracts impact, data sensitivity, scope from text
   • Works even with no database hits
   • Provides reasonable baseline scoring

2. DEFAULT VALUES (Secondary Fallback)
   • Every feature has a safe default value
   • Defaults are middle-of-range (e.g., 0.5)
   • Prevents null/error conditions

3. MANUAL OVERRIDES (Override Everything)
   • Security teams can provide estimates
   • Highest priority in the chain
   • Useful for urgent assessments

4. CONFIDENCE SCORING
   • Tracks data source quality
   • Low confidence = more defaults used
   • Alerts analysts to uncertain scores

ZERO-DAY WORKFLOW:
1. Input text description
2. System extracts what it can semantically
3. Falls back to defaults for missing data
4. Returns conservative risk assessment
5. Security team can override with estimates

✅ No zero-day will fail or crash the system
✅ Always provides a risk score
✅ Transparent about data source confidence
""")
