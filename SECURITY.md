# UCSER Security Policy & Implementation

## 🔒 Security Principles

UCSER is built on these core security principles:

1. **Defense in Depth** - Multiple layers of security controls
2. **Principle of Least Privilege** - Users only get what they need
3. **Fail Secure** - Errors result in denied access, not allowed
4. **Cryptographic Verification** - All critical operations are signed
5. **Auditability** - All actions are logged and verifiable
6. **Transparency** - Security mechanisms are documented and open to review

---

## 🛡️ Security Implementation

### Input Validation & Sanitization

**Location**: `secure_executor.py`

- **Command Validation**
  - Whitelist-based approach (safe commands only)
  - Pattern matching for injection attempts
  - Syntax validation using `shlex.split()`
  - Dangerous patterns blocked: `rm -rf`, `dd if=`, fork bombs, etc.

```python
# Example: Safe command
ctx = ExecutionContext(command="echo 'hello'", shell="bash")
valid, reason, severity = CommandValidator.validate(ctx)
# ✅ SAFE - proceeds to execution

# Example: Dangerous command
ctx = ExecutionContext(command="rm -rf /etc", shell="bash")
valid, reason, severity = CommandValidator.validate(ctx)
# ❌ BLOCKED - "Dangerous pattern detected"
```

**Test Coverage**: `tests/security/test_command_validation.py`
- 50+ injection attack patterns tested
- Command parsing edge cases
- False positive validation

---

### Role-Based Access Control (RBAC)

**Location**: `rbac_system.py`

Predefined roles with principle of least privilege:

| Role | Permissions | Use Case |
|------|-------------|----------|
| **Viewer** | Read-only access | Auditors, managers |
| **Operator** | Execute workflows | DevOps engineers |
| **Developer** | Create/modify workflows | Developers, automation |
| **Security Admin** | Policy/audit management | Security team |
| **System Admin** | Full access | Infrastructure team |

**Implementation**:
```python
# Create user with operator role
user = rbac.create_user("u1", "alice", "alice@example.com", 
                       [PredefinedRole.OPERATOR])

# Check permission
ctx = AccessContext(user=user)
allowed, reason = rbac.verify_permission(ctx, Permission.WORKFLOW_EXECUTE)
# ✅ True - operator can execute

allowed, reason = rbac.verify_permission(ctx, Permission.POLICY_DELETE)
# ❌ False - operator cannot manage policies
```

**Service Accounts**: For API/automation access
```python
account, api_key = rbac.create_service_account(
    "automation",
    [PredefinedRole.OPERATOR]
)
# Returns API key only once - must be stored securely
```

---

### Cryptographic Audit Trail

**Location**: `secure_executor.py` → `ExecutionAuditRecord`

Every execution creates an immutable, signed record:

```python
@dataclass
class ExecutionAuditRecord(BaseModel):
    audit_id: str                    # Unique identifier
    timestamp: str                   # ISO 8601 timestamp
    command_hash: str                # SHA256 of command
    policy_tags: List[str]           # Applied policies
    severity: CommandSeverity        # Risk level
    exit_code: int                   # Command result
    stdout_hash: str                 # SHA256 of output
    stderr_hash: str                 # SHA256 of errors
    duration_seconds: float          # Execution time
    executor_user: str               # Who ran it
    executor_hostname: str           # Where it ran
    digital_signature: str           # HMAC signature
    merkle_root: str                 # Merkle tree proof
```

**Verification**:
```python
# Audit record is cryptographically signed
# Can verify: command wasn't modified, output wasn't tampered with
# Creates non-repudiation (executor cannot deny running the command)
```

---

### Secrets Management

**Location**: `secrets_management.py`

Supports multiple backends for secrets storage:

1. **HashiCorp Vault** (Recommended for production)
   - Transit encryption
   - Dynamic secrets
   - Audit trail
   - Secret rotation

2. **AWS Secrets Manager**
   - Integration with AWS KMS
   - Automatic rotation
   - Resource tagging

3. **Encrypted Local Storage** (Development/fallback)
   - Fernet encryption (symmetric)
   - File-based with 0o600 permissions

**Usage**:
```python
mgr = SecretsManager.from_environment()

# Store secret
mgr.set_secret("db_password", "secure_value", tags={"env": "prod"})

# Retrieve secret (returns None if not found)
password = mgr.get_secret("db_password")

# Require secret (raises error if not found)
api_key = mgr.get_required_secret("api_key")
```

---

### Database Security

**Current**: SQLite (development only)
**Production**: PostgreSQL with hardening

**Hardening Steps**:
```bash
# 1. Enable SSL/TLS
ssl = on
ssl_cert_file = '/etc/postgresql/postgres.crt'
ssl_key_file = '/etc/postgresql/postgres.key'

# 2. Use strong passwords
ALTER ROLE ucser_user WITH PASSWORD 'STRONG_PASSWORD_32_CHARS_MIN';

# 3. Enable connection pooling
pgBouncer: max_client_conn = 1000

# 4. Restrict network access
pg_hba.conf: hostssl    all    ucser_user    0.0.0.0/0    md5

# 5. Regular backups
pg_dump ucser_prod | gzip > backup-$(date +%s).sql.gz

# 6. Monitor connections
SELECT * FROM pg_stat_activity;
```

---

### API Security

Implemented in `api/` layer:

**Authentication**:
- JWT tokens with short expiration (15 minutes)
- Refresh tokens with longer expiration (7 days)
- MFA (TOTP) optional but recommended

**Authorization**:
- Every API endpoint checks RBAC permissions
- Request signing with HMAC for non-repudiation

**Rate Limiting**:
```python
# Per-user limit: 1000 requests/hour
# Per-IP limit: 10,000 requests/hour
# Per-API-key limit: Custom (can be set per key)
```

**Input Validation**:
- Pydantic models for all request/response data
- Type checking and constraints
- Sanitization of strings

---

### Network Security

**TLS/SSL Configuration**:
```yaml
# Minimum: TLS 1.2
# Preferred: TLS 1.3
# Ciphers: Only modern, strong ciphers
# HSTS: Enabled with 1-year max-age
```

**Firewall Rules**:
```
Inbound:
- 443/tcp (HTTPS)
- 22/tcp (SSH admin only, IP-restricted)

Outbound:
- 443/tcp (to Vault, AWS, etc.)
- 5432/tcp (PostgreSQL)
- 6379/tcp (Redis)
- 53/udp (DNS)
```

**Network Segmentation**:
```
        ┌─────────────────┐
        │   Ingress/WAF   │
        │   (TLS termination)
        └────────┬────────┘
                 │
        ┌────────▼────────┐
        │ UCSER App Layer │
        │ (internal net)  │
        └────────┬────────┘
                 │
        ┌────────▼────────┐
        │ Data Layer      │
        │ (PostgreSQL,    │
        │  Redis)         │
        └─────────────────┘
```

---

## 🔑 Key Management

### Key Rotation

```bash
# Automated rotation every 90 days
vault write transit/keys/ucser_signing/rotate

# Manual rotation if compromise suspected
1. Generate new key pair
2. Keep old key in vault (temporary)
3. Update signing logic to use new key
4. Monitor for audit entries signed with old key
5. Decommission old key after verification period
```

### Key Storage

```
Private Keys:
├── Never committed to git
├── Stored in Vault (production)
├── File permissions 0o600 (development)
└── Encrypted at rest with KMS

Public Keys:
├── Can be public
├── Used for signature verification
├── Distributed with application
└── No special protection needed
```

---

## 🧪 Security Testing

### Test Suites

**1. Unit Tests** (`tests/security/`)
```bash
pytest tests/security/ -v --cov=security
# Tests RBAC, input validation, crypto
```

**2. Fuzzing/Property-Based** (`tests/fuzz/`)
```bash
pytest tests/fuzz/ -v
# Generates random commands, tests they're all validated
```

**3. Integration Tests** (`tests/integration/`)
```bash
pytest tests/integration/ -v
# Tests full execution pipeline with RBAC
```

**4. Penetration Testing** (Monthly)
- Command injection attempts
- Privilege escalation attempts
- Audit trail tampering attempts
- API abuse scenarios

---

## 📊 Security Metrics

Monitor these metrics in production:

```python
# RBAC metrics
ucser_rbac_denials_total         # Denied access attempts
ucser_rbac_permission_checks_total  # Total permission checks

# Execution metrics
ucser_execution_total            # Total executions
ucser_execution_failures_total   # Failed executions
ucser_execution_timeouts_total   # Timed-out executions

# Security metrics
ucser_dangerous_commands_blocked  # Blocked dangerous commands
ucser_injection_attempts_blocked  # Blocked injection attempts

# Audit metrics
ucser_audit_records_total        # Total audit records
ucser_signature_failures_total   # Signature verification failures
```

---

## 🚨 Incident Response

### Security Incident Process

1. **Detect**: Alert triggered (see Alerting section)
2. **Respond**: Incident commander assigned
3. **Contain**: Isolate affected systems
4. **Investigate**: Review audit logs, capture evidence
5. **Recover**: Patch vulnerability, restore service
6. **Post-Mortem**: Document lessons learned

### Emergency Procedures

**Suspected Private Key Compromise**:
```bash
1. Revoke current key in Vault
2. Generate new key pair
3. Update all systems to use new key
4. Review all audit records signed with old key
5. Notify all users of potential exposure
6. Reset all API keys and tokens
```

**Database Breach**:
```bash
1. Snapshot database (preserve evidence)
2. Rotate all database credentials
3. Rotate all API keys
4. Notify affected users
5. Review access logs for suspicious activity
```

---

## 📝 Security Compliance

### Standards Alignment

- **NIST Cybersecurity Framework**: Controls mapped
- **SOC2 Type II**: Audit logging, access controls
- **HIPAA**: Encryption, audit trails, access controls
- **PCI-DSS**: Network segmentation, access controls
- **GDPR**: Data minimization, consent tracking

### Audit Trail Retention

```
Development:  30 days
Staging:      90 days
Production:   2555 days (7 years)
```

### Data Classification

```
Public:       No encryption required
Internal:     Encrypt in transit
Confidential:  Encrypt at rest + in transit
Restricted:    Must sign every access
```

---

## 🤝 Security Contributions

### Reporting Vulnerabilities

⚠️ **DO NOT** open public GitHub issues for security vulnerabilities.

**Instead**: Email security@company.com with:
- Vulnerability description
- Affected versions
- Reproduction steps
- Proposed fix (if available)

**Response Timeline**:
- Acknowledgment: Within 24 hours
- Fix: Within 7 days (critical) or 30 days (high)
- Public disclosure: After fix released

---

## 📚 Security References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [CWE-78: Improper Neutralization of Special Elements](https://cwe.mitre.org/data/definitions/78.html)
- [SANS Top 25](https://www.sans.org/top25-software-errors/)

---

**Last Updated**: 2025-01-01  
**Version**: 1.0  
**Status**: Production-Ready ✅
