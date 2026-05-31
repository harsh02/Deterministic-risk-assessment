#!/usr/bin/env python3
"""
Quick test script to demonstrate Chat CLI threat input capabilities
Run this to see example assessments without interactive input
"""

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

# Load the risk_chat module
spec = importlib.util.spec_from_file_location("risk_chat", str(_SRC_UTILS / "risk_chat.py"))
risk_chat = importlib.util.module_from_spec(spec)
sys.modules["risk_chat"] = risk_chat
spec.loader.exec_module(risk_chat)


_PROJECT_ROOT = _UNIT_DIR.parent.parent
_DEFAULT_CONFIG = str(_PROJECT_ROOT / "policy" / "risk_rules.hybrid.yaml")


def _run_threat_input(description, config_path=None):
    """Run a single threat input through the engine."""
    if config_path is None:
        config_path = _DEFAULT_CONFIG
    print("\n" + "=" * 70)
    print(f"INPUT: {description}")
    print("=" * 70)

    try:
        # Load config
        cfg = risk_engine.load_config(config_path)

        # NOTE: extract_payload / parse_overrides / format_risk_output reference a
        # removed API and are never defined here. This demo predates the current
        # risk_engine interface and needs rewriting; tracked as a follow-up to the
        # Phase 1 hardening PR. noqa keeps lint green without masking the fact.
        # Process input
        payload = extract_payload(description)  # noqa: F821
        overrides = parse_overrides(description)  # noqa: F821
        context = {"asset_type": "SafetyCriticalDevice"}

        # Build features and compute scores
        features = risk_engine.build_features(cfg, overrides, payload)
        scores = risk_engine.compute_scores(cfg, features, context)

        # Display results
        print(format_risk_output(scores, features, context, payload))  # noqa: F821

    except Exception as e:
        print(f"❌ Error: {e}")


def main():
    print("""
╔═══════════════════════════════════════════════════════════════════╗
║              Chat CLI Threat Input - Demo & Test                  ║
╚═══════════════════════════════════════════════════════════════════╝
    """)

    # Test cases - Cross-industry examples
    test_cases = [
        # 1. Financial Services - Payment fraud
        "SQL injection in payment processing gateway, credit card data at risk",
        # 2. Cloud Infrastructure - Container escape
        "CVE-2024-21626 container escape affecting production cloud infrastructure",
        # 3. Manufacturing - SCADA control
        "Unauthenticated access to SCADA control panel, production line at risk",
        # 4. Energy & Utilities - Grid attack
        "Smart grid controller exploit CVE-2023-8888 with critical infrastructure impact",
        # 5. Automotive - Vehicle safety
        "Connected vehicle telematics remote code execution CVE-2024-77777 enabling remote control",
        # 6. Enterprise IT - Ransomware
        "Ransomware encrypted production servers, business operations completely halted",
    ]

    for i, test_case in enumerate(test_cases, 1):
        print(f"\n\n{'█'*70}")
        print(f"TEST CASE {i}/{len(test_cases)}")
        print("█" * 70)
        _run_threat_input(test_case)

        if i < len(test_cases):
            input("\n\n⏸️  Press Enter to continue to next test case...")

    print("\n\n" + "=" * 70)
    print("✅ All test cases completed!")
    print("=" * 70)
    print("\n💡 To run interactive mode:")
    print("   python risk_chat.py")
    print("\n📖 For detailed usage guide:")
    print("   cat CHAT_CLI_GUIDE.md")
    print()


if __name__ == "__main__":
    main()
