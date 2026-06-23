import hashlib
import json
import logging
from typing import Dict, Any, List, Optional, Set
from core.types import Capability, ExecutionContext
from core.ucer import ExecutionTrace, UCER

logger = logging.getLogger("Security.Sentinel")

class SecuritySentinel:
    """
    Active Behavioral Monitoring for UCSER.
    Verifies that runtime side-effects match the structural predictions.
    """
    def __init__(self, network_auditor=None):
        from security.network import NetworkAuditor
        self.network_auditor = network_auditor or NetworkAuditor()

    def inspect_trace(self, trace: ExecutionTrace, context: ExecutionContext) -> bool:
        """
        Inspects an individual execution trace for behavioral anomalies.
        """
        # 1. Verify Exit Code Parity
        if trace.exit_code != 0:
            logger.warning(f"Step {trace.step_id} failed with code {trace.exit_code}")
            # Non-zero exit code is a signal, but not necessarily a security violation

        # 2. Check for unexpected network calls if capability not granted
        if Capability.NETWORK not in context.capabilities:
            net_logs = self.network_auditor.get_audit_log(context.execution_id)
            if net_logs:
                logger.critical(f"UNAUTHORIZED NETWORK ACCESS detected for EXEC {context.execution_id}")
                return False

        # 3. Inspect Stdout/Stderr for sensitive data leakage (Heuristic)
        sensitive_patterns = ["password=", "secret=", "key=", "BEGIN RSA PRIVATE KEY"]
        output = (trace.stdout + trace.stderr).lower()
        for pattern in sensitive_patterns:
            if pattern in output:
                logger.critical(f"SENSITIVE DATA LEAKAGE detected in stdout/stderr: {pattern}")
                return False

        return True

    def validate_state_changes(self, trace: ExecutionTrace, expected: Dict[str, Any]) -> bool:
        """
        Compares observed side-effects against structural expectations.
        Example: If 'rm' was audited, we expect 'files_removed' in side_effects.
        """
        observed = trace.side_effects
        
        # Verify that all observed deletions were expected
        removed = observed.get("files_removed", [])
        expected_removed = expected.get("files_removed", [])
        
        for file in removed:
            if file not in expected_removed:
                logger.warning(f"UNEXPECTED SIDE EFFECT: File '{file}' was removed but not predicted.")
                # This could trigger an alert or a deeper audit
        
        return True
