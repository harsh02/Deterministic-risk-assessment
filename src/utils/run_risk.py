"""Batch risk assessment CLI.

Reads a JSON payload containing threat data, feature overrides, and context,
runs it through the risk engine pipeline, and writes structured results to
stdout or an output file.

Usage::

    python run_risk.py --config policy/risk_rules.hybrid.yaml --input threat.json
    python run_risk.py --config policy/risk_rules.hybrid.yaml --input threat.json --output results.json
"""

import argparse
import json

from risk_engine import build_features, compute_scores, load_config


def main():
    """Parse arguments, run the risk engine, and emit structured JSON output."""
    ap = argparse.ArgumentParser(description="Run risk assessment with database evidence")
    ap.add_argument("--config", required=True, help="Path to YAML config")
    ap.add_argument(
        "--input", required=True, help="Path to JSON with CVE/TTX/asset + overrides + context"
    )
    ap.add_argument(
        "--output", help="Path to output JSON file (optional, prints to stdout if not provided)"
    )
    args = ap.parse_args()

    cfg = load_config(args.config)
    with open(args.input, encoding="utf-8") as f:
        payload = json.load(f)

    overrides = payload.get("feature_overrides", {})
    context = payload.get("context", {})

    # Build features with DB resolution + manual overrides
    features, metadata = build_features(cfg, overrides, payload)
    scores = compute_scores(cfg, features, context)

    # Prepare output
    result = {
        "input": {
            "title": payload.get("title"),
            "description": payload.get("description"),
            "cve": payload.get("cve"),
            "ttx": payload.get("ttx"),
            "asset": payload.get("asset"),
        },
        "features": features,
        "scores": scores,
        "metadata": metadata,
    }

    temporal = metadata.get("temporal_risk") if metadata else None
    if temporal:
        result["temporal_risk"] = temporal
    elif metadata:
        status = metadata.get("temporal_risk_status")
        if status:
            result["temporal_risk_status"] = status

    # Output
    output_json = json.dumps(result, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_json)
        print(f"Results written to {args.output}")
    else:
        print(output_json)


if __name__ == "__main__":
    main()
