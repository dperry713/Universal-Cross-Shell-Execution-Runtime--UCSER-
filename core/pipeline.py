from typing import Callable, Awaitable, Optional, Set
from core.ucer import UCER
from core.types import ExecutionContext, Capability

# Define the pipeline handler type
PipelineHandler = Callable[[UCER, ExecutionContext], Awaitable[UCER]]

class BaseMiddleware:
    """
    Base class for Executor Pipeline Middleware.
    """
    def __init__(self, next_handler: Optional[PipelineHandler] = None):
        self.next_handler = next_handler

    def set_next(self, next_handler: PipelineHandler):
        self.next_handler = next_handler

    async def process(self, ucer: UCER, context: ExecutionContext) -> UCER:
        if self.next_handler:
            return await self.next_handler(ucer, context)
        return ucer

class PipelineBuilder:
    """
    Builds the async execution pipeline.
    """
    def __init__(self):
        self.middlewares = []

    def add(self, middleware: BaseMiddleware):
        self.middlewares.append(middleware)
        return self

    def build(self) -> PipelineHandler:
        """Chains middlewares together and returns the entry point."""
        if not self.middlewares:
            async def noop(u, c): return u
            return noop

        # Link from last to first
        for i in range(len(self.middlewares) - 1, 0, -1):
            self.middlewares[i - 1].set_next(self.middlewares[i].process)
            
        return self.middlewares[0].process
