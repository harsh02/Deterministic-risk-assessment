"""Reference implementation of the temporal scoring plugin.

This is a lightweight, open-source friendly calculator that mirrors the
expected interface of the proprietary module. It applies a few
heuristics so temporal scoring demos and tests can run end-to-end.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass
class _TemporalResult:
    temporal_score: float
    delta_from_base: float
    trend: str
    days_since_disclosure: int
    epss_multiplier: float
    notes: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "temporal_score": round(self.temporal_score, 2),
            "delta_from_base": round(self.delta_from_base, 2),
            "trend": self.trend,
            "days_since_disclosure": self.days_since_disclosure,
            "epss_multiplier": round(self.epss_multiplier, 2),
            "notes": self.notes,
        }


class _ReferenceTemporalCalculator:
    """Heuristic temporal calculator for demos/tests."""

    MIN_SCORE = 0.0
    MAX_SCORE = 10.0

    def calculate(
        self,
        *,
        base_score: float,
        disclosure_date: datetime,
        current_date: datetime | None = None,
        epss_score: float = 0.5,
        known_exploited: bool = False,
        kev_listed: bool = False,
        last_modified: datetime | None = None,
        adoption_hint: float | None = None,
        cve_id: str | None = None,
    ) -> dict[str, Any]:
        now = self._normalize_datetime(current_date) or datetime.now(timezone.utc)
        disclosed = self._normalize_datetime(disclosure_date) or now
        last_touch = self._normalize_datetime(last_modified) or disclosed

        days_since_disclosure = max((now - disclosed).days, 0)
        days_since_update = max((now - last_touch).days, 0)

        notes: list[str] = []
        if days_since_disclosure < 30:
            recency_adjust = 0.6
            notes.append("Recently disclosed (<30d)")
        elif days_since_disclosure < 180:
            recency_adjust = 0.2
            notes.append("Active lifecycle (≤6m)")
        else:
            decay = min((days_since_disclosure - 180) / 365.0, 1.0)
            recency_adjust = -0.2 - decay * 0.8
            notes.append("Aging disclosure (>) 6m")

        if days_since_update < 30:
            recency_adjust += 0.1
            notes.append("Recent vendor update")

        epss_multiplier = 0.75 + min(max(epss_score, 0.0), 1.0) * 0.75
        if known_exploited:
            epss_multiplier += 0.2
            notes.append("Known exploited")
        if kev_listed:
            epss_multiplier += 0.25
            notes.append("CISA KEV entry")
        epss_multiplier = min(max(epss_multiplier, 0.5), 2.0)

        adoption_boost = 0.0
        if adoption_hint is not None:
            adoption_boost = (adoption_hint - 0.5) * 1.0
            if adoption_boost > 0:
                notes.append("High adoption confidence")
            elif adoption_boost < 0:
                notes.append("Low adoption confidence")

        temporal_score = (
            base_score + recency_adjust + (epss_multiplier - 1.0) * 2.0 + adoption_boost
        )
        temporal_score = max(self.MIN_SCORE, min(self.MAX_SCORE, temporal_score))
        delta = temporal_score - base_score

        if delta > 0.4:
            trend = "rising"
        elif delta < -0.4:
            trend = "declining"
        else:
            trend = "stable"

        result = _TemporalResult(
            temporal_score=temporal_score,
            delta_from_base=delta,
            trend=trend,
            days_since_disclosure=days_since_disclosure,
            epss_multiplier=epss_multiplier,
            notes=notes,
        )
        return result.to_dict()

    @staticmethod
    def _normalize_datetime(value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


def get_temporal_calculator() -> _ReferenceTemporalCalculator:
    """Entry point expected by `temporal_proxy`."""

    return _ReferenceTemporalCalculator()
