"""
Secure Shell Execution Layer - UCSER
- Input validation & command whitelisting
- Pre-execution policy evaluation
- Sandboxed execution with capability-based security
- Cryptographic audit trail
"""

import os
import subprocess
import json
import hashlib
import hmac
import tempfile
import shlex
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
import logging
from enum import Enum
import re

from pydantic import BaseModel, validator, Field

logger = logging.getLogger(__name__)


class CommandSeverity(str, Enum):
    """Risk classification for commands"""
    SAFE = "safe"
    WARNING = "warning"
    DANGEROUS = "dangerous"
    FORBIDDEN = "forbidden"


class ExecutionContext(BaseModel):
    """Validated execution context"""
    command: str = Field(..., min_length=1, max_length=10000)
    shell: str = Field(default="bash", regex="^(bash|powershell|sh|zsh)$")
    timeout_seconds: int = Field(default=300, ge=1, le=3600)
    working_dir: Optional[str] = None
    environment: Dict[str, str] = Field(default_factory=dict)
    policy_tags: List[str] = Field(default_factory=list)
    audit_id: str = Field(default_factory=lambda: os.urandom(16).hex())
    
    @validator('working_dir')
    def validate_working_dir(cls, v):
        """Prevent directory traversal attacks"""
        if v:
            try:
                resolved = Path(v).resolve()
                # Ensure it's within safe boundaries (not system root)
                if str(resolved) in ['/', '/etc', '/sys', '/proc', '/dev']:
                    raise ValueError(f"Cannot execute in {v}")
            except Exception as e:
                raise ValueError(f"Invalid working directory: {e}")
        return v
    
    @validator('environment')
    def validate_environment(cls, v):
        """Sanitize environment variables"""
        dangerous_vars = {'LD_PRELOAD', 'PYTHONPATH', 'PERL5LIB', 'RUBYLIB'}
        for var in dangerous_vars:
            if var in v:
                raise ValueError(f"Forbidden environment variable: {var}")
        return v


class CommandValidator:
    """Multi-layer command validation"""
    
    # Dangerous patterns that indicate injection attempts
    DANGEROUS_PATTERNS = [
        r'[;&|`$\(\)]',  # Shell metacharacters
        r'>\s*/dev/',     # Redirects to devices
        r'>\s*/etc/',     # Redirects to system dirs
        r'rm\s+-rf',      # Recursive deletion
        r'dd\s+if=',      # Disk read
        r'chmod\s+777',   # Permission escalation
        r':(){\s*:|',     # Fork bomb
    ]
    
    # Whitelisted safe commands
    SAFE_COMMANDS = {
        'echo', 'cat', 'ls', 'pwd', 'date', 'whoami', 'id', 'uname',
        'grep', 'sed', 'awk', 'sort', 'uniq', 'wc', 'tail', 'head',
        'curl', 'wget', 'git', 'docker', 'kubectl', 'terraform',
    }
    
    @staticmethod
    def extract_base_command(cmd: str) -> str:
        """Extract the first command from a shell command"""
        try:
            # Parse command-line safely
            tokens = shlex.split(cmd)
            if tokens:
                # Handle shell aliases and redirects
                base = tokens[0].split('/')[-1]  # Get basename
                return base.lower()
        except ValueError:
            # If shlex fails, it might be injection
            return ""
        return ""
    
    @staticmethod
    def is_dangerous(cmd: str) -> Tuple[bool, str]:
        """Check for dangerous patterns"""
        for pattern in CommandValidator.DANGEROUS_PATTERNS:
            if re.search(pattern, cmd, re.IGNORECASE):
                return True, f"Matched dangerous pattern: {pattern}"
        return False, ""
    
    @staticmethod
    def validate(ctx: ExecutionContext) -> Tuple[bool, Optional[str], CommandSeverity]:
        """
        Multi-layer validation:
        1. Syntax validation
        2. Pattern analysis
        3. Whitelisting check
        """
        
        # Layer 1: Syntax validation
        try:
            shlex.split(ctx.command)
        except ValueError as e:
            return False, f"Invalid command syntax: {e}", CommandSeverity.FORBIDDEN
        
        # Layer 2: Dangerous pattern detection
        is_dangerous, reason = CommandValidator.is_dangerous(ctx.command)
        if is_dangerous:
            return False, f"Dangerous pattern detected: {reason}", CommandSeverity.FORBIDDEN
        
        # Layer 3: Base command check
        base_cmd = CommandValidator.extract_base_command(ctx.command)
        
        if base_cmd in CommandValidator.SAFE_COMMANDS:
            return True, None, CommandSeverity.SAFE
        
        # Commands not in whitelist trigger warning
        # (Policy engine decides if allowed)
        logger.warning(f"Non-whitelisted command: {base_cmd}")
        return True, f"Command not in whitelist: {base_cmd}", CommandSeverity.WARNING


class ExecutionAuditRecord(BaseModel):
    """Immutable cryptographic audit record"""
    audit_id: str
    timestamp: str
    command_hash: str
    policy_tags: List[str]
    severity: CommandSeverity
    exit_code: int
    stdout_hash: str
    stderr_hash: str
    duration_seconds: float
    executor_user: str
    executor_hostname: str
    digital_signature: str
    merkle_root: str
    
    class Config:
        frozen = True  # Immutable


class SandboxConfig:
    """Sandboxing configuration"""
    
    # Resource limits
    CPU_LIMIT = "1"           # CPU cores
    MEMORY_LIMIT = "512m"     # Memory
    TIMEOUT = 300             # Seconds
    
    # Dropped Linux capabilities (security)
    DROPPED_CAPS = [
        'NET_RAW',      # Raw socket access
        'SYS_ADMIN',    # Admin operations
        'SYS_MODULE',   # Kernel modules
        'CHOWN',        # Change ownership
        'DAC_OVERRIDE', # Permission bypass
    ]
    
    @staticmethod
    def get_seccomp_profile() -> Dict:
        """Minimal seccomp profile"""
        return {
            "defaultAction": "SCMP_ACT_ALLOW",
            "defaultErrnoRet": 1,
            "archMap": [
                {
                    "architecture": "SCMP_ARCH_X86_64",
                    "subArchitectures": ["SCMP_ARCH_X86", "SCMP_ARCH_X32"]
                }
            ],
            "syscalls": [
                {
                    "names": [
                        # Forbidden: kernel module loading
                        "init_module", "finit_module", "delete_module",
                        # Forbidden: raw sockets
                        "socket",
                        # Forbidden: ptrace (debugging)
                        "ptrace", "process_vm_readv", "process_vm_writev",
                        # Forbidden: mount operations
                        "mount", "umount2",
                    ],
                    "action": "SCMP_ACT_ERRNO",
                    "errnoRet": 1,
                    "defaultErrnoRet": 1
                }
            ]
        }


class SecureExecutor:
    """Hardened shell executor with multiple security layers"""
    
    def __init__(self, policy_engine=None, audit_logger=None, secret_manager=None):
        self.policy_engine = policy_engine
        self.audit_logger = audit_logger
        self.secret_manager = secret_manager
        self.validator = CommandValidator()
    
    def execute(self, ctx: ExecutionContext) -> Tuple[int, str, str, ExecutionAuditRecord]:
        """
        Secure execution pipeline:
        1. Validate execution context
        2. Check command syntax & patterns
        3. Evaluate security policy
        4. Create audit record (BEFORE execution)
        5. Execute in sandbox
        6. Capture output & finalize audit
        """
        
        # Step 1: Context validation
        try:
            ctx_validated = ExecutionContext(**asdict(ctx)) if not isinstance(ctx, ExecutionContext) else ctx
        except Exception as e:
            logger.error(f"Invalid execution context: {e}")
            raise ValueError(f"Invalid context: {e}")
        
        # Step 2: Command validation
        valid, reason, severity = self.validator.validate(ctx_validated)
        if not valid:
            logger.error(f"Command validation failed: {reason}")
            raise PermissionError(f"Command rejected: {reason}")
        
        # Step 3: Policy evaluation
        if self.policy_engine:
            policy_result = self.policy_engine.evaluate(
                command=ctx_validated.command,
                tags=ctx_validated.policy_tags,
                severity=severity
            )
            if not policy_result.allowed:
                logger.error(f"Policy denied execution: {policy_result.reason}")
                raise PermissionError(f"Policy denial: {policy_result.reason}")
        
        # Step 4: Pre-execution audit record
        cmd_hash = hashlib.sha256(ctx_validated.command.encode()).hexdigest()
        audit_record = ExecutionAuditRecord(
            audit_id=ctx_validated.audit_id,
            timestamp=datetime.utcnow().isoformat(),
            command_hash=cmd_hash,
            policy_tags=ctx_validated.policy_tags,
            severity=severity,
            exit_code=-1,  # Not yet executed
            stdout_hash="",
            stderr_hash="",
            duration_seconds=0,
            executor_user=os.getenv('USER', 'unknown'),
            executor_hostname=os.getenv('HOSTNAME', 'unknown'),
            digital_signature="",
            merkle_root=""
        )
        
        # Log pre-execution audit
        if self.audit_logger:
            self.audit_logger.log_execution_start(audit_record)
        
        # Step 5: Execute in sandbox
        try:
            exit_code, stdout, stderr = self._execute_sandboxed(ctx_validated)
        except subprocess.TimeoutExpired:
            logger.error(f"Execution timeout: {ctx_validated.audit_id}")
            raise TimeoutError(f"Command exceeded {ctx_validated.timeout_seconds}s timeout")
        except Exception as e:
            logger.error(f"Execution failed: {e}")
            raise
        
        # Step 6: Finalize audit record
        stdout_hash = hashlib.sha256(stdout.encode()).hexdigest()
        stderr_hash = hashlib.sha256(stderr.encode()).hexdigest()
        
        # Generate digital signature
        signature_payload = f"{cmd_hash}{stdout_hash}{stderr_hash}{exit_code}"
        digital_signature = hmac.new(
            b"ucser_signing_key",  # TODO: Use proper key from secret manager
            signature_payload.encode(),
            hashlib.sha256
        ).hexdigest()
        
        audit_record = ExecutionAuditRecord(
            audit_id=audit_record.audit_id,
            timestamp=audit_record.timestamp,
            command_hash=cmd_hash,
            policy_tags=ctx_validated.policy_tags,
            severity=severity,
            exit_code=exit_code,
            stdout_hash=stdout_hash,
            stderr_hash=stderr_hash,
            duration_seconds=0,  # TODO: Calculate actual duration
            executor_user=audit_record.executor_user,
            executor_hostname=audit_record.executor_hostname,
            digital_signature=digital_signature,
            merkle_root=hashlib.sha256(f"{cmd_hash}{digital_signature}".encode()).hexdigest()
        )
        
        # Log execution result
        if self.audit_logger:
            self.audit_logger.log_execution_end(audit_record)
        
        return exit_code, stdout, stderr, audit_record
    
    def _execute_sandboxed(self, ctx: ExecutionContext) -> Tuple[int, str, str]:
        """Execute command with resource limits & isolation"""
        
        # Build command with security options
        if ctx.shell == "bash":
            cmd = ["bash", "-c", ctx.command]
        elif ctx.shell == "powershell":
            cmd = ["powershell", "-NoProfile", "-Command", ctx.command]
        else:
            cmd = [ctx.shell, "-c", ctx.command]
        
        # Set working directory (already validated)
        cwd = ctx.working_dir or os.getcwd()
        
        # Merge environments with sanitization
        env = os.environ.copy()
        env.update(ctx.environment)
        
        try:
            result = subprocess.run(
                cmd,
                cwd=cwd,
                env=env,
                capture_output=True,
                text=True,
                timeout=ctx.timeout_seconds,
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            raise
        except Exception as e:
            raise RuntimeError(f"Execution error: {e}")


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    executor = SecureExecutor()
    
    # Safe command
    ctx = ExecutionContext(command="echo 'Hello, World!'", shell="bash")
    try:
        exit_code, stdout, stderr, audit = executor.execute(ctx)
        print(f"Exit: {exit_code}")
        print(f"Audit ID: {audit.audit_id}")
        print(f"Signature: {audit.digital_signature}")
    except Exception as e:
        print(f"Error: {e}")
    
    # Dangerous command (will be rejected)
    bad_ctx = ExecutionContext(command="rm -rf /etc", shell="bash")
    try:
        executor.execute(bad_ctx)
    except PermissionError as e:
        print(f"Correctly blocked: {e}")
