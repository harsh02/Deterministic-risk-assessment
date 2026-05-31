"""
Semantic search for CVEs and MITRE TTPs using sentence-transformers.

This module provides embedding-based similarity search to find relevant
CVEs and MITRE ATT&CK techniques from vague threat descriptions.
"""

import json
import logging
from pathlib import Path

import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

logger = logging.getLogger(__name__)

# Global model cache
_model = None
_cve_embeddings = None
_cve_metadata = None
_mitre_embeddings = None
_mitre_metadata = None
_ics_embeddings = None
_ics_metadata = None
_ics_model_id = None

ICS_STUB_PATH = Path(__file__).parent / "mitre_ics_stub.json"
ICS_BENIGN_HINTS = {
    "training",
    "test bench",
    "lab",
    "simulator",
    "non-production",
    "demo",
    "staging",
    "no intrusion",
    "reboot",
    "maintenance",
}
ICS_CRITICAL_HINTS = {
    "safety",
    "trip",
    "shutdown",
    "overpressure",
    "chemical",
    "boiler",
    "turbine",
    "fire",
}


def load_model(model_name: str = "all-MiniLM-L6-v2") -> SentenceTransformer:
    """
    Load sentence-transformer model (cached).

    Models:
    - all-MiniLM-L6-v2: Fast, 384-dim (default)
    - all-mpnet-base-v2: Better quality, 768-dim
    - multi-qa-mpnet-base-dot-v1: Best for questions
    """
    global _model
    if _model is None:
        logger.info(f"Loading semantic model: {model_name}")
        _model = SentenceTransformer(model_name)
        logger.info(f"Model loaded: {_model.get_sentence_embedding_dimension()}-dim embeddings")
    return _model


def embed_text(text: str, model: SentenceTransformer | None = None) -> np.ndarray:
    """Generate embedding for a single text string."""
    if model is None:
        model = load_model()
    return model.encode(text, convert_to_numpy=True, normalize_embeddings=True)


def embed_batch(
    texts: list[str],
    model: SentenceTransformer | None = None,
    batch_size: int = 32,
    show_progress: bool = True,
) -> np.ndarray:
    """Generate embeddings for a batch of texts."""
    if model is None:
        model = load_model()
    return model.encode(
        texts,
        batch_size=batch_size,
        convert_to_numpy=True,
        normalize_embeddings=True,
        show_progress_bar=show_progress,
    )


def load_cve_index(index_dir: Path) -> tuple[np.ndarray, list[dict]]:
    """Load pre-built CVE embeddings and metadata."""
    global _cve_embeddings, _cve_metadata

    if _cve_embeddings is None:
        emb_path = index_dir / "cve_embeddings.npy"
        meta_path = index_dir / "cve_metadata.json"

        if not emb_path.exists() or not meta_path.exists():
            raise FileNotFoundError(
                f"CVE index not found at {index_dir}. Run build_indexes.py first."
            )

        logger.info(f"Loading CVE index from {index_dir}")
        _cve_embeddings = np.load(emb_path)
        with open(meta_path) as f:
            _cve_metadata = json.load(f)
        logger.info(f"Loaded {len(_cve_metadata)} CVE embeddings")

    return _cve_embeddings, _cve_metadata


def load_mitre_index(index_dir: Path) -> tuple[np.ndarray, list[dict]]:
    """Load pre-built MITRE ATT&CK embeddings and metadata."""
    global _mitre_embeddings, _mitre_metadata

    if _mitre_embeddings is None:
        emb_path = index_dir / "mitre_embeddings.npy"
        meta_path = index_dir / "mitre_metadata.json"

        if not emb_path.exists() or not meta_path.exists():
            raise FileNotFoundError(
                f"MITRE index not found at {index_dir}. Run build_indexes.py first."
            )

        logger.info(f"Loading MITRE index from {index_dir}")
        _mitre_embeddings = np.load(emb_path)
        with open(meta_path) as f:
            _mitre_metadata = json.load(f)
        logger.info(f"Loaded {len(_mitre_metadata)} MITRE embeddings")

    return _mitre_embeddings, _mitre_metadata


def load_ics_stub_index(
    model: SentenceTransformer | None = None,
) -> tuple[np.ndarray | None, list[dict]]:
    """Load curated ICS ATT&CK stub embeddings and metadata."""
    global _ics_embeddings, _ics_metadata, _ics_model_id

    if not ICS_STUB_PATH.exists():
        logger.warning("ICS MITRE stub not found at %s", ICS_STUB_PATH)
        return None, []

    if model is None:
        model = load_model()

    model_id = id(model)

    if _ics_embeddings is not None and _ics_model_id == model_id:
        return _ics_embeddings, _ics_metadata or []

    try:
        with ICS_STUB_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        logger.error("ICS stub JSON invalid: %s", exc)
        return None, []

    techniques = data.get("techniques", [])
    if not techniques:
        logger.warning("ICS stub contains no techniques")
        return None, []

    texts = []
    metadata = []
    for item in techniques:
        technique_id = item.get("technique_id") or item.get("id")
        name = item.get("name", "")
        description = item.get("description", "")
        if not technique_id or not description:
            continue

        search_text = f"{technique_id} {name}: {description}"
        texts.append(search_text)
        metadata.append(
            {
                "technique_id": technique_id,
                "name": name,
                "description": description[:500],
                "tactics": item.get("tactics", []),
                "ics_assets": item.get("ics_assets", []),
                "example": item.get("example"),
                "domain": "ics",
                "keywords": item.get("keywords", []),
                "severity_hint": item.get("severity_hint", "medium"),
                "contexts": item.get("contexts", []),
            }
        )

    if not texts:
        logger.warning("ICS stub techniques missing required fields")
        return None, []

    embeddings = model.encode(
        texts,
        batch_size=16,
        convert_to_numpy=True,
        normalize_embeddings=True,
        show_progress_bar=False,
    )

    _ics_embeddings = embeddings
    _ics_metadata = metadata
    _ics_model_id = model_id

    logger.info("Loaded %d ICS stub techniques", len(metadata))
    return _ics_embeddings, _ics_metadata


def search_cves(
    query: str,
    index_dir: Path,
    top_k: int = 5,
    min_similarity: float = 0.7,
    model: SentenceTransformer | None = None,
    query_embedding: np.ndarray | None = None,
) -> list[dict]:
    """
    Semantic search for CVEs matching the query.

    Args:
        query: Natural language threat description
        index_dir: Directory containing cve_embeddings.npy and cve_metadata.json
        top_k: Number of results to return
        min_similarity: Minimum cosine similarity threshold (0-1)
        model: Optional pre-loaded model
        query_embedding: Optional pre-computed embedding (avoids re-encoding)

    Returns:
        List of dicts with: cve_id, description, similarity, cvss_score, etc.
    """
    embeddings, metadata = load_cve_index(index_dir)

    if model is None:
        model = load_model()

    # Use pre-computed embedding if provided, otherwise embed now
    if query_embedding is not None:
        query_emb = query_embedding.reshape(1, -1)
    else:
        query_emb = embed_text(query, model).reshape(1, -1)

    # Compute similarities
    similarities = cosine_similarity(query_emb, embeddings)[0]

    # Get top-k indices above threshold
    top_indices = np.argsort(similarities)[::-1][: top_k * 2]  # Get 2x in case filtering

    results = []
    for idx in top_indices:
        sim = float(similarities[idx])
        if sim < min_similarity:
            continue

        result = metadata[idx].copy()
        result["similarity"] = round(sim, 3)
        results.append(result)

        if len(results) >= top_k:
            break

    logger.info(f"CVE search: '{query[:50]}...' → {len(results)} matches")
    return results


def search_mitre_ttps(
    query: str,
    index_dir: Path,
    top_k: int = 5,
    min_similarity: float = 0.7,
    model: SentenceTransformer | None = None,
    domain: str = "enterprise",
    query_embedding: np.ndarray | None = None,
) -> list[dict]:
    """
    Semantic search for MITRE ATT&CK techniques matching the query.

    Args:
        query: Natural language threat description
        index_dir: Directory containing mitre_embeddings.npy and mitre_metadata.json
        top_k: Number of results to return
        min_similarity: Minimum cosine similarity threshold (0-1)
        model: Optional pre-loaded model
        domain: "enterprise" (default) or "ics" for the curated ICS stub
        query_embedding: Optional pre-computed embedding (avoids re-encoding)

    Returns:
        List of dicts with: technique_id, name, description, similarity, tactics, etc.
    """
    if model is None:
        model = load_model()

    embeddings = metadata = None
    if domain == "ics":
        embeddings, metadata = load_ics_stub_index(model)
        if embeddings is None or metadata is None or len(metadata) == 0:
            logger.warning("Falling back to enterprise MITRE index for ICS search")
            embeddings = metadata = None

    if embeddings is None or metadata is None:
        embeddings, metadata = load_mitre_index(index_dir)

    # Domain-specific tuning: ICS stub is small, so allow a lower threshold
    sim_threshold = min_similarity
    if domain == "ics" and min_similarity >= 0.5:
        sim_threshold = 0.4

    # Use pre-computed embedding if provided, otherwise embed now
    if query_embedding is not None:
        query_emb = query_embedding.reshape(1, -1)
    else:
        query_emb = embed_text(query, model).reshape(1, -1)
    query_lower = query.lower()

    # Compute similarities
    similarities = cosine_similarity(query_emb, embeddings)[0]

    # Get top-k indices above threshold
    top_indices = np.argsort(similarities)[::-1][: top_k * 2]

    results = []
    for idx in top_indices:
        sim = float(similarities[idx])
        adj_sim = sim

        if domain == "ics":
            meta = metadata[idx]
            keywords = meta.get("keywords", [])
            contexts = meta.get("contexts", [])
            severity_hint = meta.get("severity_hint", "medium")

            keyword_hits = 0
            for kw in keywords:
                if kw and kw.lower() in query_lower:
                    keyword_hits += 1
            adj_sim += min(0.03 * keyword_hits, 0.09)

            benign_query = any(hint in query_lower for hint in ICS_BENIGN_HINTS)
            critical_query = any(hint in query_lower for hint in ICS_CRITICAL_HINTS)

            if benign_query and ("training" in contexts or severity_hint in {"low", "benign"}):
                adj_sim += 0.05
            elif benign_query and severity_hint in {"high", "critical"}:
                adj_sim -= 0.05

            if critical_query and severity_hint in {"high", "critical"}:
                adj_sim += 0.03
            elif critical_query and severity_hint in {"low", "benign"}:
                adj_sim -= 0.03

            if contexts:
                matched_context = any(ctx in query_lower for ctx in contexts)
                if matched_context:
                    adj_sim += 0.04

            adj_sim = float(np.clip(adj_sim, 0.0, 1.0))
        else:
            adj_sim = sim
        if adj_sim < sim_threshold:
            continue

        result = metadata[idx].copy()
        result["similarity"] = round(adj_sim, 3)
        if domain == "ics":
            result["similarity_raw"] = round(sim, 3)
        results.append(result)

        if len(results) >= top_k:
            break

    if not results and domain == "ics" and len(metadata) > 0:
        # Fallback: return the best available match even if below threshold
        best_idx = int(np.argmax(similarities))
        fallback = metadata[best_idx].copy()
        fallback["similarity"] = round(float(similarities[best_idx]), 3)
        results.append(fallback)

    label = "ICS" if domain == "ics" else "MITRE"
    logger.info(f"{label} search: '{query[:50]}...' → {len(results)} matches")
    return results


def search_combined(
    query: str,
    index_dir: Path,
    top_k_cves: int = 5,
    top_k_ttps: int = 5,
    min_similarity: float = 0.7,
) -> dict[str, list[dict]]:
    """
    Search both CVEs and MITRE TTPs in one call.

    Returns:
        {
            'cves': [...],
            'ttps': [...],
            'query': str
        }
    """
    model = load_model()  # Load once for both searches

    cves = search_cves(query, index_dir, top_k_cves, min_similarity, model)
    ttps = search_mitre_ttps(query, index_dir, top_k_ttps, min_similarity, model)

    return {"query": query, "cves": cves, "ttps": ttps}
