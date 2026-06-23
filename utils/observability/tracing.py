import uuid
import contextvars
import time
from typing import Optional

# Context-local storage for the current trace ID
_trace_id_var = contextvars.ContextVar("trace_id", default=None)

class Tracer:
    """
    Distributed tracing utility for UCSER.
    Ensures a single trace_id propagates across all modules for a given intent.
    """
    
    @staticmethod
    def start_trace(trace_id: Optional[str] = None) -> str:
        """Sets the current trace ID for the context."""
        tid = trace_id or str(uuid.uuid4())
        _trace_id_var.set(tid)
        return tid

    @staticmethod
    def get_current_trace_id() -> Optional[str]:
        """Retrieves the current trace ID."""
        return _trace_id_var.get()

    @staticmethod
    def clear_trace():
        """Clears the trace ID from the current context."""
        _trace_id_var.set(None)

class Span:
    """
    Represents a logical unit of work within a trace.
    Captures duration and metadata.
    """
    def __init__(self, name: str, metadata: Optional[dict] = None):
        self.name = name
        self.metadata = metadata or {}
        self.trace_id = Tracer.get_current_trace_id()
        self.start_time = None
        self.end_time = None

    def __enter__(self):
        self.start_time = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end_time = time.perf_counter()
        duration_ms = (self.end_time - self.start_time) * 1000
        # In a full implementation, this would emit to a collector like Jaeger or OTel
        # logger.info(f"Span {self.name} finished in {duration_ms:.2f}ms", extra={"trace_id": self.trace_id, "duration": duration_ms})
