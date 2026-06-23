from typing import Callable, Dict, Any
import logging

logger = logging.getLogger("Kernel.IPC")

class SyscallIPC:
    """
    Message bus for isolated component communication.
    Prevents direct coupling between modules.
    """
    def __init__(self):
        self._handlers: Dict[int, Callable] = {}
        
    def register_syscall(self, syscall_id: int, handler: Callable):
        if syscall_id in self._handlers:
            raise ValueError(f"Syscall {syscall_id} already registered.")
        self._handlers[syscall_id] = handler
        
    def invoke(self, syscall_id: int, ctx: Any, *args, **kwargs) -> Any:
        """
        Invokes a syscall. The context (ctx) represents the calling process
        and is mandatory for security tracking.
        """
        if syscall_id not in self._handlers:
            raise ValueError(f"Unknown syscall: {syscall_id}")
        
        # In a real kernel, context switches and capability checks happen here
        # For UCSER, we pass the ProcessContext to the handler
        logger.debug(f"Syscall {syscall_id} invoked by PID {ctx.pid if ctx else 'KERNEL'}")
        try:
            return self._handlers[syscall_id](ctx, *args, **kwargs)
        except Exception as e:
            logger.error(f"Syscall {syscall_id} failed: {e}")
            raise
