import functools
import inspect
from typing import Set, Callable, Any
from core.types import Capability, ExecutionContext

class FormalContract:
    """
    Mathematical capability enforcement for AST nodes and execution paths.
    Acts as a declarative security boundary before execution logic runs.
    """
    @staticmethod
    def requires(required_caps: Set[Capability]) -> Callable:
        """
        Decorator that asserts the ExecutionContext possesses the required capabilities.
        Extracts context from keyword arguments or assumes standard positional injection.
        """
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs) -> Any:
                # Attempt to extract context dynamically
                context = kwargs.get('context')
                if not context:
                    # Search args for ExecutionContext
                    for arg in args:
                        if isinstance(arg, ExecutionContext):
                            context = arg
                            break
                
                if context:
                    if not required_caps.issubset(context.capabilities):
                        missing = required_caps - context.capabilities
                        raise PermissionError(
                            f"Contract Violation in {func.__name__}. "
                            f"Missing Capabilities: {missing}"
                        )
                else:
                    # In a strict mathematical model, failure to provide context is a violation.
                    raise PermissionError(f"Contract Violation: No ExecutionContext provided to {func.__name__}.")
                    
                return func(*args, **kwargs)
            return wrapper
        return decorator
