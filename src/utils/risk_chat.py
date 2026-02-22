"""Interactive REPL for natural-language risk assessment.

Provides a chat-style interface where users type free-text threat
descriptions, CVE IDs, or MITRE technique references. The engine
extracts structured fields, runs the full risk pipeline, and
prints scored results with evidence summaries.

Supports optional manual overrides via inline key=value syntax
(e.g., ``cvss=7.8  kev=1``) for calibration or testing.
"""

import logging
import re
import importlib.util
import subprocess
import sys

# Load the risk_engine module
spec = importlib.util.spec_from_file_location("risk_engine", "risk_engine.py")
risk_engine = importlib.util.module_from_spec(spec)
sys.modules["risk_engine"] = risk_engine
spec.loader.exec_module(risk_engine)

load_config = risk_engine.load_config
build_features = risk_engine.build_features
compute_scores = risk_engine.compute_scores

logger = logging.getLogger(__name__)

BANNER = """\
╔═══════════════════════════════════════════════════════════════════╗
║         Risk Assessment Chat - Threat & Vulnerability Input       ║
╚═══════════════════════════════════════════════════════════════════╝

🔍 Natural Language Input - Just describe the threat!

📝 Examples (Cross-Industry):
  • "Ransomware encrypted our production servers, operations down for 3 days"
  • "CVE-2024-21413 remote code execution in Microsoft Outlook, actively exploited"
  • "SQL injection in payment gateway, credit card data exposed"
  • "Phishing attack targeting employees, credentials stolen"
  • "Industrial IoT sensors compromised, SCADA system at risk"
  • "Zero-day in VPN gateway, remote access to corporate network"

🎯 Auto-Detection:
  ✓ CVE IDs       (CVE-2024-12345) → CVSS scores from NVD
  ✓ MITRE TTX     (T1190) → Attack frequency from ATT&CK
  ✓ Asset names   → Maturity from EMB3D
  ✓ Safety terms  ("patient safety", "injury", "production") → Safety flag

⚡ Optional Manual Overrides (Advanced):
  cvss=7.8  exp=3.1  kev=1  af=0.4  sm=0.2  safety=1  asset=BackendService

🏢 Asset Types:
  asset=SafetyCriticalDevice | BackendService | InternalTool

💡 Commands:
  help     - Show this banner again
  examples - Show threat input examples
  clear    - Clear screen
  quit     - Exit

Type your threat or vulnerability description below:
"""

EXAMPLES = """\
╔═══════════════════════════════════════════════════════════════════╗
║                   Threat Input Examples (All Industries)          ║
╚═══════════════════════════════════════════════════════════════════╝

🏢 ENTERPRISE IT & CLOUD
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. SQL injection vulnerability in production database, unauthorized data access

2. CVE-2024-21626 container escape affecting cloud infrastructure

3. Authentication bypass in admin portal allowing full system access

4. Misconfigured S3 bucket exposing customer personal information


💰 FINANCIAL SERVICES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
5. SQL injection in payment processing gateway, credit card data at risk

6. Man-in-the-middle attack on ATM network communication

7. Mobile banking app session hijacking CVE-2024-99999 with transaction manipulation


🏭 MANUFACTURING & INDUSTRIAL  
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
8. Unauthenticated access to SCADA control panel, production at risk

9. CVE-2024-54321 buffer overflow in PLC firmware affecting production line safety

10. Default credentials on industrial IoT sensors enabling network pivoting


🛒 RETAIL & E-COMMERCE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
11. Price manipulation vulnerability in e-commerce checkout process

12. POS malware stealing payment card data from retail terminals

13. Customer database breach exposing millions of records


🏥 HEALTHCARE (Non-Medical Device)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
14. EHR system vulnerability CVE-2024-88888 exposing patient medical records

15. Ransomware encrypted hospital systems, patient care operations halted

16. Phishing campaign targeting healthcare staff with credential-stealing malware


⚡ ENERGY & UTILITIES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
17. Smart grid controller exploit CVE-2023-8888 causing widespread outages

18. Water treatment SCADA system hack affecting chemical dosing systems

19. Electrical substation physical and cyber attack with rogue hardware


🚗 AUTOMOTIVE & TRANSPORTATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
20. Connected vehicle telematics remote code execution CVE-2024-77777

21. Fleet management GPS spoofing attack affecting logistics operations

22. Autonomous vehicle sensor blinding attack bypassing safety systems


💡 TIP: Copy any line above and paste into the Chat CLI!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📖 For 100+ more examples across 15+ industries, see:
   • GENERIC_THREATS.md - Comprehensive industry examples
   • TOP_20_THREATS.md - Most common threat templates
"""

def parse_overrides(text: str):
    """Extract key=value pairs from free text and map them to feature names.

    Supported aliases: cvss, exp, kev, af, sm, safety. Unknown keys are
    passed through as-is so users can set any feature directly.
    """
    # key aliases to feature names
    aliases = {
        "cvss": "CVSS_BaseScore",
        "exp": "CVSS_Exploitability",
        "kev": "KnownExploited",
        "af": "Attack_Frequency",
        "sm": "System_Maturity",
        "safety": "Safety_Impact_Flag",
    }
    overrides = {}
    for k, v in re.findall(r"(\b[a-zA-Z_]+)\s*=\s*([0-9.]+)", text):
        key = aliases.get(k.lower(), k)
        try:
            overrides[key] = float(v)
        except ValueError as exc:
            logger.debug("Skipping override %s=%s due to parse error: %s", key, v, exc)
    return overrides

def extract_payload(text: str):
    """Extract CVE, TTX, and asset mentions from free text"""
    payload = {}
    
    # Extract CVE ID (e.g., CVE-2024-12345)
    cve_match = re.search(r"\b(CVE-\d{4}-\d{4,7})\b", text, re.IGNORECASE)
    if cve_match:
        payload["cve"] = cve_match.group(1).upper()
    
    # Extract MITRE ATT&CK technique (e.g., T1190, T1203.001)
    ttx_match = re.search(r"\b(T\d{4}(?:\.\d{3})?)\b", text, re.IGNORECASE)
    if ttx_match:
        payload["ttx"] = ttx_match.group(1).upper()
    
    # Extract potential asset names (various patterns)
    # Pattern 1: After "in", "affecting", "on"
    asset_patterns = [
        r'(?:in|affecting|on|for)\s+([A-Z][A-Za-z\s]+(?:device|system|server|platform|service|tool|mammography|therapy|imaging)[A-Za-z\s]*)',
        r'"([^"]+)"',  # Quoted strings
        r'asset[:\s]+([A-Za-z][A-Za-z\s]+)',  # Explicit asset mention
    ]
    
    for pattern in asset_patterns:
        asset_match = re.search(pattern, text, re.IGNORECASE)
        if asset_match:
            payload["asset"] = asset_match.group(1).strip()
            break
    
    # Add title and description for safety keyword matching
    payload["title"] = text[:100]  # First 100 chars as title
    payload["description"] = text
    
    return payload

def score_to_band(score: float) -> tuple:
    """Convert a normalized 0–1 score to a 1–10 band with label and indicator.

    Returns:
        Tuple of (band_number, category_label, color_indicator).
    """
    band = min(10, max(1, int(score * 10) + 1))  # Convert to 1-10
    
    if band >= 9:
        return (band, "Critical", "🔴")
    elif band >= 7:
        return (band, "High", "🟠")
    elif band >= 4:
        return (band, "Medium", "🟡")
    elif band >= 2:
        return (band, "Low", "🟢")
    else:
        return (band, "Negligible", "⚪")

def format_risk_output(scores, features, context, payload, metadata=None):
    """Format the risk assessment output nicely with full evidence chain"""
    output = []
    
    # Detection summary
    output.append("\n" + "="*70)
    output.append("📊 RISK ASSESSMENT RESULT")
    output.append("="*70)
    
    # Show semantic matches first (NEW!)
    if metadata and metadata.get("evidence"):
        cve_matches = []
        ttp_matches = []
        
        for evidence in metadata["evidence"]:
            if evidence.get("match_type") == "semantic":
                if "cve_id" in evidence:
                    cve_matches.append(evidence)
                elif "technique_id" in evidence:
                    ttp_matches.append(evidence)
        
        if cve_matches:
            output.append("\n🔍 MATCHED CVEs (Semantic Search):")
            for ev in cve_matches:
                sim = ev.get("similarity", 0) * 100
                output.append(f"   • {ev['cve_id']} (Similarity: {sim:.0f}%)")
                output.append(f"     CVSS: {ev.get('features', {}).get('CVSS_BaseScore', 0):.1f}")
                if ev.get("all_matches"):
                    output.append(f"     📚 Found {len(ev['all_matches'])} total matches")
                    for i, match in enumerate(ev["all_matches"][1:4], 2):  # Show top 3 more
                        output.append(f"        {i}. {match['cve_id']} ({match['similarity']*100:.0f}%)")
        
        if ttp_matches:
            output.append("\n🎯 MATCHED MITRE TTPs (Semantic Search):")
            for ev in ttp_matches:
                sim = ev.get("similarity", 0) * 100
                output.append(f"   • {ev['technique_id']} - {ev.get('technique_name', 'Unknown')}")
                output.append(f"     Similarity: {sim:.0f}% | Tactics: {', '.join(ev.get('tactics', []))}")
                if ev.get("all_matches"):
                    output.append(f"     📚 Found {len(ev['all_matches'])} total matches")
                    for i, match in enumerate(ev["all_matches"][1:4], 2):
                        output.append(f"        {i}. {match['technique_id']} - {match['name']} ({match['similarity']*100:.0f}%)")
    
    # Auto-detected exact matches
    if any(payload.get(k) for k in ["cve", "ttx", "asset"]):
        output.append("\n🔍 Auto-Detected (Exact Match):")
        if payload.get("cve"):
            output.append(f"   • CVE: {payload['cve']}")
        if payload.get("ttx"):
            output.append(f"   • MITRE TTX: {payload['ttx']}")
        if payload.get("asset"):
            output.append(f"   • Asset: {payload['asset']}")
    
    # Convert scores to bands
    likelihood_band, likelihood_cat, likelihood_emoji = score_to_band(scores['likelihood'])
    severity_band, severity_cat, severity_emoji = score_to_band(scores['severity'])
    
    # Risk scores with bands (1-10 scale)
    output.append("\n📈 Risk Scores:")
    output.append(f"   • Likelihood:     {likelihood_emoji} {likelihood_band}/10 ({likelihood_cat})")
    output.append(f"   • Severity:       {severity_emoji} {severity_band}/10 ({severity_cat})")
    
    # Overall risk with color indicator
    risk_level = scores['overall_risk']
    risk_emoji = {
        "Critical": "🔴",
        "High": "🟠", 
        "Medium": "🟡",
        "Low": "🟢",
        "Negligible": "⚪"
    }
    emoji = risk_emoji.get(risk_level, "⚪")
    output.append(f"   • Overall Risk:   {emoji} {risk_level} (5x5 Matrix)")
    criticality_band = int(scores['context_criticality'] * 10)
    output.append(f"   • Criticality:    {criticality_band}/10")

    if metadata and metadata.get("temporal_risk"):
        tr = metadata["temporal_risk"]
        arrow_map = {
            "rising": "⬆️",
            "declining": "⬇️",
            "stable": "➡️",
        }
        delta = tr.get("delta_from_base", 0.0)
        arrow = arrow_map.get(tr.get("trend", "stable"), "➡️")
        output.append("\n⏱️ Temporal Risk (Patent Pending):")
        output.append(
            f"   • Adjusted Score: {arrow} {tr.get('temporal_score', 0.0):.1f}/10 (Δ {delta:+.1f})"
        )
        output.append(
            f"   • Disclosure Age: {tr.get('days_since_disclosure', 'N/A')} days | EPS Factor: {tr.get('epss_multiplier', 0.0):.2f}"
        )
        notes = tr.get("notes") or []
        if notes:
            output.append(f"   • Signals: {', '.join(notes[:3])}")
    elif metadata and metadata.get("temporal_risk_status"):
        output.append("\n⏱️ Temporal Risk: unavailable")
        output.append(
            f"   • Reason: {metadata['temporal_risk_status']} (requires proprietary module)"
        )
    
    # Feature breakdown (1-10 scale)
    output.append("\n📋 Feature Breakdown:")
    for name, value in features.items():
        # Convert 0-1 to 1-10 scale
        value_10 = int(value * 10) if value <= 1.0 else int(value)
        bar_length = int((value_10 / 10.0) * 20)  # 20 char bar
        bar = "█" * bar_length + "░" * (20 - bar_length)
        output.append(f"   {name:25} [{bar}] {value_10}/10")
    
    # Context
    output.append(f"\n🏢 Context: {context.get('asset_type', 'Unknown')}")
    output.append("="*70)
    
    return "\n".join(output)

def main():
    import os
    from pathlib import Path
    
    # Try to find config file in multiple locations
    possible_paths = [
        "risk_rules.hybrid.yaml",  # Current directory
        "../policy/risk_rules.hybrid.yaml",  # Parent/policy
        "../../policy/risk_rules.hybrid.yaml",  # Two levels up/policy
    ]
    
    config_path = None
    for path in possible_paths:
        if Path(path).exists():
            config_path = path
            break
    
    if not config_path:
        print("❌ Error: Cannot find risk_rules.hybrid.yaml")
        print("   Searched locations:")
        for path in possible_paths:
            print(f"   - {path}")
        print("\n💡 Please run from the correct directory or specify config path")
        return
    
    try:
        cfg = load_config(config_path)
        print(f"✅ Loaded config from: {config_path}\n")
    except Exception as e:
        print(f"❌ Error loading config: {e}")
        return
        
    print(BANNER)
    context = {"asset_type": "BackendService"}  # default; change per message if provided
    
    assessment_history = []
    
    while True:
        try:
            msg = input("\n💬 You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n\n👋 Goodbye!")
            break
            
        if not msg:
            continue
            
        # Handle commands
        if msg.lower() in {"quit", "exit", "q"}:
            print("\n👋 Goodbye!")
            break
        elif msg.lower() == "help":
            print(BANNER)
            continue
        elif msg.lower() == "examples":
            print(EXAMPLES)
            continue
        elif msg.lower() == "clear":
            subprocess.run(["clear"] if os.name != "nt" else ["cmd", "/c", "cls"], check=False)
            print(BANNER)
            continue
        elif msg.lower() == "history":
            if not assessment_history:
                print("\n📜 No assessments yet.")
            else:
                print("\n📜 Assessment History:")
                for i, item in enumerate(assessment_history, 1):
                    print(f"\n{i}. {item['description'][:60]}...")
                    print(f"   Risk: {item['risk']} | Likelihood: {item['likelihood']:.2f} | Severity: {item['severity']:.2f}")
            continue

        # parse quick context
        m_asset = re.search(r"\basset\s*=\s*([A-Za-z]+)", msg)
        if m_asset:
            context["asset_type"] = m_asset.group(1)

        # Extract CVE, TTX, asset from message for DB resolution
        payload = extract_payload(msg)
        payload["description"] = msg  # Add full description for NLP extractors
        
        # Parse manual overrides (highest priority)
        overrides = parse_overrides(msg)

        # Build features with DB resolution + manual overrides
        try:
            features, metadata = build_features(cfg, overrides, payload)
            scores = compute_scores(cfg, features, context)
            
            # Display formatted output
            print(format_risk_output(scores, features, context, payload, metadata))
            
            # Save to history
            assessment_history.append({
                "description": msg,
                "risk": scores["overall_risk"],
                "likelihood": scores["likelihood"],
                "severity": scores["severity"],
                "context": context.copy()
            })
            
        except Exception as e:
            print(f"\n❌ Error processing assessment: {e}")
            print("💡 Try 'help' for usage examples or 'examples' for threat templates")

if __name__ == "__main__":
    main()
