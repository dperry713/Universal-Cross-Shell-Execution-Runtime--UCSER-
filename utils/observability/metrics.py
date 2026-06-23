import time
import threading
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger("Utils.Metrics")

class MetricsCollector:
    """
    In-memory metrics collector with thread-safe aggregation.
    Designed for high-performance execution tracking.
    """
    def __init__(self):
        self._counts: Dict[str, int] = {}
        self._latencies: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def increment(self, name: str, value: int = 1):
        with self._lock:
            self._counts[name] = self._counts.get(name, 0) + value

    def record_latency(self, name: str, value: float):
        with self._lock:
            if name not in self._latencies:
                self._latencies[name] = []
            self._latencies[name].append(value)
            # Keep a window of the last 1000 measurements
            if len(self._latencies[name]) > 1000:
                self._latencies[name].pop(0)

    def get_snapshot(self) -> Dict[str, Any]:
        with self._lock:
            snapshot = {"counts": dict(self._counts), "latencies": {}}
            for name, values in self._latencies.items():
                if values:
                    snapshot["latencies"][name] = {
                        "avg": sum(values) / len(values),
                        "max": max(values),
                        "p95": sorted(values)[int(len(values) * 0.95)] if len(values) >= 20 else values[-1],
                        "count": len(values)
                    }
            return snapshot

    def reset(self):
        with self._lock:
            self._counts.clear()
            self._latencies.clear()

# Global singleton for current process
metrics = MetricsCollector()

class TelemetryProvider:
    """
    Orchestrates the broadcasting of telemetry events to the Unified Data Bus.
    """
    def __init__(self, databus=None):
        self.databus = databus

    async def emit_execution_metric(self, ucer_id: str, adapter: str, duration_ms: float, success: bool):
        """Broadcasts execution performance data to the cluster."""
        event = {
            "type": "execution_metric",
            "ucer_id": ucer_id,
            "adapter": adapter,
            "duration_ms": duration_ms,
            "success": success,
            "timestamp": time.time()
        }
        
        # Local Aggregation
        metrics.increment(f"exec.count.{adapter}")
        metrics.increment(f"exec.success" if success else "exec.failure")
        metrics.record_latency(f"exec.latency.{adapter}", duration_ms)
        
        if self.databus:
            await self.databus.publish_event("telemetry.execution", event)
