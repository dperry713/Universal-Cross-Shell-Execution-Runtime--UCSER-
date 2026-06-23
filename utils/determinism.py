import os
import time
import random
import logging
from typing import Any

logger = logging.getLogger("Utils.Determinism")

class DeterminismGuard:
    """
    Utilities for enforcing deterministic behavior in the execution environment.
    Handles clock mocking, seed stabilization, and environment sanitization.
    """
    
    @staticmethod
    def sanitize_env(env: dict) -> dict:
        """
        Removes non-deterministic environment variables (e.g., RANDOM, SHLVL, PWD).
        """
        ignore_keys = {'RANDOM', 'SHLVL', 'PWD', 'OLDPWD', '_', 'PS1'}
        return {k: v for k, v in env.items() if k not in ignore_keys}

    @staticmethod
    def freeze_time(target_time: float = None):
        """
        Mocks time.time() to return a constant value for the current thread/process.
        In a real system, this would use 'libfaketime' or 'freezegun'.
        """
        fixed = target_time or 1781700000.0
        # This is a simplified mock for demonstration
        import time as _time
        _time.time = lambda: fixed
        logger.info(f"Execution time frozen at {fixed}")

    @staticmethod
    def stabilize_random(seed: int = 42):
        """Seeds all common random number generators."""
        random.seed(seed)
        try:
            import numpy as np
            np.random.seed(seed)
        except ImportError:
            pass
        logger.info(f"Random seed stabilized: {seed}")
