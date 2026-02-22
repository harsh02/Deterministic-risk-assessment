"""Adapter for the temporal risk scoring plugin.

The public repository exposes only this loader.  The actual temporal
calculation implementation is supplied out-of-band via
``detrisk_internal.temporal`` or any compatible package that provides a
``get_temporal_calculator()`` factory returning an object with a
``calculate(**kwargs)`` method.

When the plugin is not installed, a null calculator is returned and all
callers receive ``None`` results, keeping the open-source build fully
functional without temporal scoring.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class _NullTemporalCalculator:
    __slots__ = ()

    def calculate(  # type: ignore[override]
        self,
        *,
        base_score: float,
        disclosure_date: datetime,
        current_date: Optional[datetime] = None,
        epss_score: float = 0.5,
        known_exploited: bool = False,
        kev_listed: bool = False,
        last_modified: Optional[datetime] = None,
        adoption_hint: Optional[float] = None,
        cve_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        return None


_NULL_CALCULATOR = _NullTemporalCalculator()
_cached_calculator: Any = None
_loader_status: Optional[str] = None


def _load_calculator() -> Any:
    global _loader_status
    try:
        from detrisk_internal.temporal import get_temporal_calculator as loader  # type: ignore
    except ModuleNotFoundError:
        _loader_status = "plugin_not_installed"
        logger.info("Temporal plugin not installed; skipping temporal scoring.")
        return _NULL_CALCULATOR
    except Exception as exc:  # pragma: no cover - defensive guardrail
        _loader_status = f"plugin_load_failed: {exc}"
        logger.warning("Temporal plugin failed to load: %s", exc)
        return _NULL_CALCULATOR

    try:
        calculator = loader()
    except Exception as exc:  # pragma: no cover - defensive guardrail
        _loader_status = f"plugin_factory_failed: {exc}"
        logger.warning("Temporal plugin factory raised: %s", exc)
        return _NULL_CALCULATOR

    _loader_status = "ok"
    return calculator


def get_temporal_calculator() -> Any:
    """Return the active temporal calculator or a stub if unavailable."""
    global _cached_calculator
    if _cached_calculator is None:
        _cached_calculator = _load_calculator()
    return _cached_calculator


def temporal_plugin_ready() -> bool:
    """Whether a real temporal calculator is available."""
    calc = get_temporal_calculator()
    return calc is not _NULL_CALCULATOR


def temporal_plugin_status() -> Optional[str]:
    """Return loader status for diagnostics."""
    global _loader_status
    if _loader_status is None:
        _ = get_temporal_calculator()
    return _loader_status
