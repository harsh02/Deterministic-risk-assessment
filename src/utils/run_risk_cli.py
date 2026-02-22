"""Simple CLI wrapper for the DetRisk risk engine.

Usage examples (from repo root):

    cd src/utils
    .venv/bin/python run_risk_cli.py \
        --config ../../policy/risk_rules.hybrid.yaml \
        --title "Remote code execution in Outlook via crafted links" \\
        --description "CVE-2024-21413 allows unauthenticated RCE via moniker link."

This will print the core risk scores and a compact
summary of evidence sources used.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict

import yaml

from risk_engine import build_features, compute_scores


def load_config(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    # Attach config file path so relative sources resolve correctly
    cfg["__config_file__"] = str(path)
    return cfg


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run DetRisk risk engine on a single input payload.")

    parser.add_argument(
        "--config",
        required=False,
        help=(
            "Path to risk_rules.hybrid.yaml; if omitted, defaults to "
            "../../policy/risk_rules.hybrid.yaml relative to this script."
        ),
    )

    parser.add_argument("--title", help="Short title or summary of the threat.", default="")
    parser.add_argument("--description", help="Detailed description of the threat.", default="")

    parser.add_argument("--cve", help="Optional CVE identifier (e.g. CVE-2023-12345).", default="")
    parser.add_argument("--ttp", "--ttx", dest="ttx", help="Optional MITRE ATT&CK technique ID.", default="")

    parser.add_argument(
        "--json-input",
        help="Optional path to a JSON file with full input payload; CLI flags will override overlapping fields.",
        default="",
    )

    return parser.parse_args()


def build_payload(args: argparse.Namespace) -> Dict[str, Any]:
    payload: Dict[str, Any] = {}

    if args.json_input:
        path = Path(args.json_input)
        with path.open("r", encoding="utf-8") as f:
            payload = json.load(f)

    if args.title:
        payload["title"] = args.title
    if args.description:
        payload["description"] = args.description
    if args.cve:
        payload["cve"] = args.cve
    if args.ttx:
        payload["ttx"] = args.ttx

    return payload


def main() -> None:
    args = parse_args()

    # Default config path if not provided
    if args.config:
        cfg_path = Path(args.config).expanduser().resolve()
    else:
        cfg_path = (Path(__file__).parent / "../../policy/risk_rules.hybrid.yaml").resolve()
    cfg = load_config(cfg_path)

    payload = build_payload(args)

    features, metadata = build_features(cfg, overrides={}, input_payload=payload)

    # Core scores using configured formulas
    context = {"asset_type": payload.get("asset_type")} if isinstance(payload, dict) else {}
    scores = compute_scores(cfg, features, context)

    print("=== Core Scores ===")
    print(json.dumps({
        "likelihood": scores.get("likelihood"),
        "severity": scores.get("severity"),
        "overall_risk": scores.get("overall_risk"),
        "severity_mode": scores.get("severity_mode"),
    }, indent=2))

    # Evidence overview
    sources = sorted({ev.get("source") for ev in metadata.get("evidence", []) if isinstance(ev, dict) and ev.get("source")})
    print("\n=== Evidence Sources ===")
    print(json.dumps(sources, indent=2))


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    main()
