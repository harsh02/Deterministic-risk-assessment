"""Internal DetRisk modules shipped alongside the open-source risk engine."""

from .temporal import get_temporal_calculator  # re-export for convenience

__all__ = ["get_temporal_calculator"]
