#!/usr/bin/env python3
"""Build semantic search indexes for CVEs and MITRE ATT&CK techniques.

Reads the NVD and MITRE ATT&CK JSON databases, generates sentence-transformer
embeddings for each entry, and writes the results as NumPy arrays alongside
JSON metadata files under ``indexes/``.

These pre-built indexes enable fast similarity search in ``semantic_search.py``
when no exact CVE ID or technique ID is provided in the threat input.

Outputs:
    indexes/cve_embeddings.npy    -- Embedding vectors for CVE descriptions.
    indexes/cve_metadata.json     -- CVE IDs, descriptions, CVSS scores.
    indexes/mitre_embeddings.npy  -- Embedding vectors for MITRE techniques.
    indexes/mitre_metadata.json   -- Technique IDs, names, tactics.
"""

import json
import logging
import sys
from pathlib import Path

import numpy as np
from tqdm import tqdm

# Import after checking environment. Logging isn't configured yet at this point,
# so report the missing dependency directly to stderr before exiting.
try:
    from sentence_transformers import SentenceTransformer
except ImportError:
    print(
        "sentence-transformers not installed. Run: pip install sentence-transformers",
        file=sys.stderr,
    )
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def build_cve_index(
    nvd_file: Path, output_dir: Path, model_name: str = "all-MiniLM-L6-v2", max_cves: int = None
):
    """
    Build semantic index for CVEs from NVD database.

    Args:
        nvd_file: Path to nvdcve-2.0-modified.json
        output_dir: Directory to save embeddings and metadata
        model_name: Sentence-transformer model
        max_cves: Limit processing (for testing), None = all
    """
    logger.info(f"Loading NVD database from {nvd_file}")
    with open(nvd_file) as f:
        nvd_data = json.load(f)

    vulnerabilities = nvd_data.get("vulnerabilities", [])
    logger.info(f"Found {len(vulnerabilities)} CVEs in database")

    if max_cves:
        vulnerabilities = vulnerabilities[:max_cves]
        logger.info(f"Limiting to {max_cves} CVEs for testing")

    # Extract CVE data
    cve_texts = []
    cve_metadata = []

    logger.info("Extracting CVE descriptions...")
    for vuln in tqdm(vulnerabilities):
        cve_obj = vuln.get("cve", {})
        cve_id = cve_obj.get("id", "")

        if not cve_id:
            continue

        # Get description
        descriptions = cve_obj.get("descriptions", [])
        desc_text = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                desc_text = desc.get("value", "")
                break

        if not desc_text:
            continue

        # Get CVSS scores
        metrics = cve_obj.get("metrics", {})
        cvss_score = 0.0
        cvss_exploitability = 0.0

        # Try v3.1, v3.0, v2.0 in priority order
        for version in ["cvssMetricV31", "cvssMetricV3", "cvssMetricV2"]:
            if version in metrics and len(metrics[version]) > 0:
                metric = metrics[version][0]
                cvss_data = metric.get("cvssData", {})
                cvss_score = float(cvss_data.get("baseScore", 0))
                cvss_exploitability = float(metric.get("exploitabilityScore", 0))
                break

        # Create search text: combine CVE ID + description for better matching
        search_text = f"{cve_id}: {desc_text}"
        cve_texts.append(search_text)

        cve_metadata.append(
            {
                "cve_id": cve_id,
                "description": desc_text[:500],  # Truncate for storage
                "cvss_score": cvss_score,
                "cvss_exploitability": cvss_exploitability,
            }
        )

    logger.info(f"Extracted {len(cve_texts)} CVEs with descriptions")

    # Load model and generate embeddings
    logger.info(f"Loading model: {model_name}")
    model = SentenceTransformer(model_name)

    logger.info("Generating CVE embeddings (this may take a few minutes)...")
    embeddings = model.encode(
        cve_texts,
        batch_size=64,
        show_progress_bar=True,
        convert_to_numpy=True,
        normalize_embeddings=True,
    )

    # Save to disk
    output_dir.mkdir(parents=True, exist_ok=True)

    emb_path = output_dir / "cve_embeddings.npy"
    meta_path = output_dir / "cve_metadata.json"

    logger.info(f"Saving embeddings to {emb_path}")
    np.save(emb_path, embeddings)

    logger.info(f"Saving metadata to {meta_path}")
    with open(meta_path, "w") as f:
        json.dump(cve_metadata, f, indent=2)

    logger.info(
        f"✅ CVE index built: {len(cve_metadata)} CVEs, {embeddings.shape[1]}-dim embeddings"
    )
    return embeddings, cve_metadata


def build_mitre_index(mitre_file: Path, output_dir: Path, model_name: str = "all-MiniLM-L6-v2"):
    """
    Build semantic index for MITRE ATT&CK techniques.

    Args:
        mitre_file: Path to enterprise-attack.json
        output_dir: Directory to save embeddings and metadata
        model_name: Sentence-transformer model
    """
    logger.info(f"Loading MITRE ATT&CK from {mitre_file}")
    with open(mitre_file) as f:
        mitre_data = json.load(f)

    objects = mitre_data.get("objects", [])
    logger.info(f"Found {len(objects)} objects in MITRE database")

    # Extract techniques
    technique_texts = []
    technique_metadata = []

    logger.info("Extracting MITRE techniques...")
    for obj in tqdm(objects):
        obj_type = obj.get("type", "")

        # Only process attack-pattern (techniques)
        if obj_type != "attack-pattern":
            continue

        # Skip revoked/deprecated
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        technique_id = None
        for ext_ref in obj.get("external_references", []):
            if ext_ref.get("source_name") == "mitre-attack":
                technique_id = ext_ref.get("external_id")
                break

        if not technique_id:
            continue

        name = obj.get("name", "")
        description = obj.get("description", "")

        if not description:
            continue

        # Get tactics (kill chain phases)
        tactics = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                tactics.append(phase.get("phase_name", ""))

        # Create search text: ID + name + description
        search_text = f"{technique_id} {name}: {description}"
        technique_texts.append(search_text)

        technique_metadata.append(
            {
                "technique_id": technique_id,
                "name": name,
                "description": description[:500],  # Truncate
                "tactics": tactics,
            }
        )

    logger.info(f"Extracted {len(technique_texts)} MITRE techniques")

    # Load model and generate embeddings
    logger.info(f"Loading model: {model_name}")
    model = SentenceTransformer(model_name)

    logger.info("Generating MITRE embeddings...")
    embeddings = model.encode(
        technique_texts,
        batch_size=64,
        show_progress_bar=True,
        convert_to_numpy=True,
        normalize_embeddings=True,
    )

    # Save to disk
    output_dir.mkdir(parents=True, exist_ok=True)

    emb_path = output_dir / "mitre_embeddings.npy"
    meta_path = output_dir / "mitre_metadata.json"

    logger.info(f"Saving embeddings to {emb_path}")
    np.save(emb_path, embeddings)

    logger.info(f"Saving metadata to {meta_path}")
    with open(meta_path, "w") as f:
        json.dump(technique_metadata, f, indent=2)

    logger.info(
        f"✅ MITRE index built: {len(technique_metadata)} techniques, {embeddings.shape[1]}-dim embeddings"
    )
    return embeddings, technique_metadata


def main():
    """Build both indexes."""
    import argparse

    parser = argparse.ArgumentParser(description="Build semantic search indexes")
    parser.add_argument(
        "--data-dir",
        type=str,
        default="../../data",
        help="Directory containing nvdcve-2.0-modified.json and enterprise-attack.json",
    )
    parser.add_argument(
        "--output-dir", type=str, default="../../indexes", help="Directory to save embeddings"
    )
    parser.add_argument(
        "--model", type=str, default="all-MiniLM-L6-v2", help="Sentence-transformer model name"
    )
    parser.add_argument(
        "--max-cves", type=int, default=None, help="Limit CVEs for testing (default: process all)"
    )
    parser.add_argument("--cve-only", action="store_true", help="Build only CVE index")
    parser.add_argument("--mitre-only", action="store_true", help="Build only MITRE index")

    args = parser.parse_args()

    data_dir = Path(args.data_dir).resolve()
    output_dir = Path(args.output_dir).resolve()

    logger.info(f"Data directory: {data_dir}")
    logger.info(f"Output directory: {output_dir}")
    logger.info(f"Model: {args.model}")

    # Build CVE index
    if not args.mitre_only:
        nvd_file = data_dir / "nvdcve-2.0-modified.json"
        if not nvd_file.exists():
            logger.error(f"NVD file not found: {nvd_file}")
        else:
            build_cve_index(nvd_file, output_dir, args.model, args.max_cves)

    # Build MITRE index
    if not args.cve_only:
        mitre_file = data_dir / "enterprise-attack.json"
        if not mitre_file.exists():
            logger.error(f"MITRE file not found: {mitre_file}")
        else:
            build_mitre_index(mitre_file, output_dir, args.model)

    logger.info("✅ All indexes built successfully!")


if __name__ == "__main__":
    main()
