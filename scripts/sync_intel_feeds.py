#!/usr/bin/env python3
"""Synchronise public threat-intel feeds required by DetRisk.

Downloads threat-intelligence artefacts into ``data/`` and writes
``*.meta.json`` sidecar files for ETag / SHA-256 tracking.

Architecture
------------

* **Feed registry** — definitions live in ``policy/feeds.yaml``; add or
  remove feeds without touching code.
* **Streaming I/O** — downloads and decompression are chunked so memory
  stays bounded regardless of payload size.
* **Concurrent** — independent feeds are fetched in parallel via
  ``ThreadPoolExecutor``.
* **Retry with back-off** — transient HTTP errors are retried up to *N*
  times with exponential delay.
* **Structured logging** — all output flows through the ``logging`` module
  with configurable verbosity.

Security: HTTPS-only, byte budgets (compressed + decompressed), SHA-256
integrity verification, no eval/exec.

Usage::

    python scripts/sync_intel_feeds.py              # incremental refresh
    python scripts/sync_intel_feeds.py --force       # re-download everything
    python scripts/sync_intel_feeds.py --only epss,nvd
    python scripts/sync_intel_feeds.py --workers 8   # override concurrency
    python scripts/sync_intel_feeds.py -v            # debug logging
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import logging
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterable, Optional
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from zipfile import ZipFile

import yaml

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
FEEDS_YAML = ROOT / "policy" / "feeds.yaml"
META_SUFFIX = ".meta.json"
CHUNK_SIZE = 64 * 1024  # 64 KB streaming chunks

log = logging.getLogger("detrisk.sync")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Feed:
    """Single intelligence feed descriptor — populated from YAML."""

    name: str
    slug: str
    url: str
    destination: Path
    max_bytes: int
    decompress: str | None = None          # "zip" | "gzip" | None
    extract_name: str | None = None        # file inside a ZIP archive
    max_unpacked_bytes: int | None = None
    manual_guidance: str | None = None


@dataclass(frozen=True)
class SyncSettings:
    """Operational knobs — populated from the ``settings:`` section."""

    max_workers: int = 4
    retry_attempts: int = 3
    retry_backoff_base: float = 2.0
    request_timeout: int = 90
    user_agent: str = "detrisk-sync/1.0 (+https://github.com/)"


# ---------------------------------------------------------------------------
# YAML registry loader
# ---------------------------------------------------------------------------

def _load_registry() -> tuple[dict[str, Feed], dict, SyncSettings]:
    """Parse ``policy/feeds.yaml`` into typed objects."""
    raw = yaml.safe_load(FEEDS_YAML.read_text("utf-8"))

    feeds: dict[str, Feed] = {}
    for slug, cfg in raw.get("feeds", {}).items():
        feeds[slug] = Feed(
            name=cfg["name"],
            slug=slug,
            url=cfg["url"],
            destination=ROOT / cfg["destination"],
            max_bytes=cfg["max_bytes"],
            decompress=cfg.get("decompress"),
            extract_name=cfg.get("extract_name"),
            max_unpacked_bytes=cfg.get("max_unpacked_bytes"),
            manual_guidance=cfg.get("manual_guidance"),
        )

    mitre_cfg = raw.get("mitre", {})

    settings_raw = raw.get("settings", {})
    settings = SyncSettings(**settings_raw)

    return feeds, mitre_cfg, settings


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _safe_domain(url: str) -> None:
    """Reject anything that isn't HTTPS."""
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        raise ValueError(f"Refusing non-HTTPS resource: {url}")


def _hash_file(path: Path) -> str:
    """Stream-hash *path* with SHA-256 in CHUNK_SIZE pieces."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            h.update(chunk)
    return h.hexdigest()


def _read_meta(meta_path: Path) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Return ``(etag, last_modified, sha256)`` from a sidecar meta file."""
    if not meta_path.exists():
        return None, None, None
    try:
        payload = json.loads(meta_path.read_text("utf-8"))
        return payload.get("etag"), payload.get("last_modified"), payload.get("sha256")
    except Exception:
        return None, None, None


def _write_meta(
    meta_path: Path,
    *,
    etag: str | None,
    last_modified: str | None,
    sha256: str,
) -> None:
    meta_path.write_text(
        json.dumps(
            {
                "etag": etag,
                "last_modified": last_modified,
                "sha256": sha256,
                "synced_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def _verify_existing(
    destination: Path,
    expected_sha: Optional[str],
) -> tuple[bool, Optional[str]]:
    """Check whether the file on disk matches the stored SHA-256."""
    if not destination.exists() or not expected_sha:
        return False, None
    actual = _hash_file(destination)
    return actual == expected_sha, actual


# ---------------------------------------------------------------------------
# Retry wrapper
# ---------------------------------------------------------------------------

def _with_retry(fn, *, attempts: int = 3, backoff_base: float = 2.0):
    """Call *fn* up to *attempts* times with exponential back-off."""
    last_exc: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            return fn()
        except Exception as exc:
            last_exc = exc
            if attempt < attempts:
                delay = backoff_base ** (attempt - 1)
                log.warning(
                    "Attempt %d/%d failed: %s — retrying in %.1fs",
                    attempt,
                    attempts,
                    exc,
                    delay,
                )
                time.sleep(delay)
            else:
                log.error("All %d attempts exhausted", attempts)
    raise last_exc  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Streaming download
# ---------------------------------------------------------------------------

def _stream_download(
    url: str,
    tmp_path: Path,
    max_bytes: int,
    *,
    settings: SyncSettings,
    etag: str | None,
    modified: str | None,
) -> tuple[bool, dict[str, str]]:
    """Stream *url* to *tmp_path* in CHUNK_SIZE pieces.

    Returns ``(downloaded, response_headers)``.
    *downloaded* is ``False`` when the server returns **304 Not Modified**.
    """
    _safe_domain(url)
    hdrs: dict[str, str] = {"User-Agent": settings.user_agent}
    if etag:
        hdrs["If-None-Match"] = etag
    if modified:
        hdrs["If-Modified-Since"] = modified

    ctx = ssl.create_default_context()
    req = Request(url, headers=hdrs)

    try:
        with urlopen(req, context=ctx, timeout=settings.request_timeout) as resp:
            resp_hdrs = {k.title(): v for k, v in resp.headers.items()}
            resp_hdrs["Status-Code"] = str(resp.getcode())

            total = 0
            with open(tmp_path, "wb") as fout:
                while chunk := resp.read(CHUNK_SIZE):
                    total += len(chunk)
                    if total > max_bytes:
                        tmp_path.unlink(missing_ok=True)
                        raise RuntimeError(
                            f"Download exceeds {max_bytes:,}-byte limit "
                            f"at {total:,} bytes"
                        )
                    fout.write(chunk)

            return True, resp_hdrs

    except HTTPError as err:
        if err.code == 304:
            resp_hdrs = {k.title(): v for k, v in err.headers.items()}
            resp_hdrs["Status-Code"] = "304"
            return False, resp_hdrs
        raise


# ---------------------------------------------------------------------------
# Streaming decompression
# ---------------------------------------------------------------------------

def _decompress_to(feed: Feed, src: Path, dest: Path) -> None:
    """Decompress *src* → *dest* in a streaming fashion, enforcing size."""
    limit = feed.max_unpacked_bytes or feed.max_bytes
    written = 0

    if feed.decompress == "gzip":
        with gzip.open(src, "rb") as gin, open(dest, "wb") as fout:
            while chunk := gin.read(CHUNK_SIZE):
                written += len(chunk)
                if written > limit:
                    dest.unlink(missing_ok=True)
                    raise RuntimeError(
                        f"{feed.name}: decompressed payload exceeds "
                        f"{limit:,}-byte limit"
                    )
                fout.write(chunk)

    elif feed.decompress == "zip":
        target = feed.extract_name
        with ZipFile(src) as archive:
            members = archive.namelist()
            target = target or (members[0] if members else None)
            if not target:
                raise RuntimeError(f"{feed.name}: empty ZIP archive")
            with archive.open(target) as zin, open(dest, "wb") as fout:
                while chunk := zin.read(CHUNK_SIZE):
                    written += len(chunk)
                    if written > limit:
                        dest.unlink(missing_ok=True)
                        raise RuntimeError(
                            f"{feed.name}: decompressed payload exceeds "
                            f"{limit:,}-byte limit"
                        )
                    fout.write(chunk)

    else:
        # No decompression — atomic move
        src.replace(dest)
        return

    # Clean up the compressed temp file
    src.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Per-feed sync (runs in its own thread)
# ---------------------------------------------------------------------------

def _sync_feed(feed: Feed, *, force: bool, settings: SyncSettings) -> bool:
    """Download / verify a single feed.  Returns True if new data landed."""
    destination = feed.destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    meta_path = destination.with_suffix(destination.suffix + META_SUFFIX)
    etag, last_modified, stored_sha = _read_meta(meta_path)

    # Verify existing file integrity via streaming hash
    checksum_ok, actual_sha = _verify_existing(destination, stored_sha)
    force_dl = force

    if checksum_ok and not force_dl:
        log.info("%s: up-to-date (local checksum verified)", feed.name)
        return False

    if actual_sha and stored_sha and actual_sha != stored_sha:
        log.warning(
            "%s: checksum mismatch (expected %s…, got %s…) — re-downloading",
            feed.name,
            stored_sha[:12],
            actual_sha[:12],
        )
        force_dl = True

    # Stream download with retry + exponential back-off
    tmp_path = destination.with_suffix(destination.suffix + ".tmp")

    def _do_download():
        return _stream_download(
            feed.url,
            tmp_path,
            feed.max_bytes,
            settings=settings,
            etag=None if force_dl else etag,
            modified=None if force_dl else last_modified,
        )

    try:
        downloaded, headers = _with_retry(
            _do_download,
            attempts=settings.retry_attempts,
            backoff_base=settings.retry_backoff_base,
        )

        if not downloaded:
            log.info("%s: not modified (server 304)", feed.name)
            return False

        # Streaming decompression (or atomic rename for raw feeds)
        _decompress_to(feed, tmp_path, destination)

        # Stream-hash the final artefact
        sha = _hash_file(destination)
        size = destination.stat().st_size

        _write_meta(
            meta_path,
            etag=headers.get("Etag"),
            last_modified=headers.get("Last-Modified"),
            sha256=sha,
        )

        log.info(
            "%s: downloaded (%s bytes, sha256=%s…)",
            feed.name,
            f"{size:,}",
            sha[:12],
        )
        return True

    finally:
        # Clean up temp file on any failure path
        tmp_path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# MITRE bundle check
# ---------------------------------------------------------------------------

def _check_mitre_bundle(mitre_cfg: dict) -> None:
    expected = ROOT / mitre_cfg.get(
        "expected_path", "data/enterprise-attack.json"
    )
    guidance = mitre_cfg.get(
        "guidance",
        "Download from https://github.com/mitre/cti/releases and place "
        "'enterprise-attack.json' under data/.",
    )
    if expected.exists():
        sha = _hash_file(expected)
        size = expected.stat().st_size
        log.info(
            "MITRE ATT&CK bundle present (%s bytes, sha256=%s…)",
            f"{size:,}",
            sha[:12],
        )
    else:
        log.warning("MITRE ATT&CK bundle missing. %s", guidance)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Synchronise DetRisk intelligence feeds",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="re-download feeds even if hashes match",
    )
    parser.add_argument(
        "--only",
        metavar="SLUGS",
        help="comma-separated list of feed slugs to sync",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help="override max concurrent downloads (default: from feeds.yaml)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="enable DEBUG-level logging",
    )
    return parser.parse_args(list(argv))


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: Iterable[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])
    _setup_logging(args.verbose)

    # Load feed registry
    if not FEEDS_YAML.exists():
        log.error("Feed registry not found: %s", FEEDS_YAML)
        return 2

    feeds, mitre_cfg, settings = _load_registry()

    # CLI override for worker count
    if args.workers:
        settings = SyncSettings(
            max_workers=args.workers,
            retry_attempts=settings.retry_attempts,
            retry_backoff_base=settings.retry_backoff_base,
            request_timeout=settings.request_timeout,
            user_agent=settings.user_agent,
        )

    # Filter to requested slugs
    selected = set(feeds)
    if args.only:
        requested = {
            s.strip().lower() for s in args.only.split(",") if s.strip()
        }
        unknown = requested - set(feeds)
        if unknown:
            log.error("Unknown feed slug(s): %s", ", ".join(sorted(unknown)))
            return 2
        selected = requested

    log.info(
        "DetRisk threat-intel sync (%d feed(s), %d worker(s))",
        len(selected),
        settings.max_workers,
    )
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # ── Concurrent download ───────────────────────────────────
    results: dict[str, bool | Exception] = {}

    with ThreadPoolExecutor(max_workers=settings.max_workers) as pool:
        futures = {
            pool.submit(
                _sync_feed,
                feeds[slug],
                force=args.force,
                settings=settings,
            ): slug
            for slug in sorted(selected)
        }
        for future in as_completed(futures):
            slug = futures[future]
            try:
                results[slug] = future.result()
            except Exception as exc:
                results[slug] = exc
                feed = feeds[slug]
                log.error("%s: FAILED — %s", feed.name, exc)
                if feed.manual_guidance and "403" in str(exc):
                    log.info("  Manual action: %s", feed.manual_guidance)

    _check_mitre_bundle(mitre_cfg)

    # ── Summary ───────────────────────────────────────────────
    any_downloaded = any(v is True for v in results.values())
    any_failed = any(isinstance(v, Exception) for v in results.values())

    if any_failed:
        log.warning("Sync completed with errors.")
    elif any_downloaded:
        log.info("Sync complete.")
    else:
        log.info("All selected feeds are current.")

    return 1 if any_failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
