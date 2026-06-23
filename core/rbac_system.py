"""
RBAC System for UCSER - Role-Based Access Control
Enforces principle of least privilege across all operations
"""

import json
from typing import List, Set, Dict, Optional, Tuple
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging

from pydantic import BaseModel, validator

logger = logging.getLogger(__name__)


class Permission(str, Enum):
    """Core permissions"""
    # Workflow management
    WORKFLOW_CREATE = "workflow:create"
    WORKFLOW_READ = "workflow:read"
    WORKFLOW_UPDATE = "workflow:update"
    WORKFLOW_DELETE = "workflow:delete"
    WORKFLOW_EXECUTE = "workflow:execute"
    WORKFLOW_STOP = "workflow:stop"
    
    # Execution management
    EXECUTION_VIEW = "execution:view"
    EXECUTION_LOGS = "execution:logs"
    
    # Policy management
    POLICY_READ = "policy:read"
    POLICY_CREATE = "policy:create"
    POLICY_UPDATE = "policy:update"
    POLICY_DELETE = "policy:delete"
    
    # Audit & security
    AUDIT_READ = "audit:read"
    AUDIT_EXPORT = "audit:export"
    SECRETS_READ = "secrets:read"
    SECRETS_WRITE = "secrets:write"
    
    # Admin operations
    ADMIN_USERS = "admin:users"
    ADMIN_CONFIG = "admin:config"
    ADMIN_SYSTEM = "admin:system"


class PredefinedRole(str, Enum):
    """Built-in roles with principle of least privilege"""
    VIEWER = "viewer"           # Read-only access
    OPERATOR = "operator"       # Execute workflows, view results
    DEVELOPER = "developer"     # Create/modify workflows
    SECURITY_ADMIN = "security_admin"  # Audit & policy management
    SYSTEM_ADMIN = "admin"      # Full access


class RoleDefinition(BaseModel):
    """Definition of a role and its permissions"""
    name: str
    description: str
    permissions: Set[Permission]
    max_concurrent_executions: int = 10
    max_execution_duration_minutes: int = 60
    resource_limits: Dict[str, int] = {}
    
    class Config:
        use_enum_values = False


# Default role definitions
DEFAULT_ROLES: Dict[PredefinedRole, RoleDefinition] = {
    PredefinedRole.VIEWER: RoleDefinition(
        name="Viewer",
        description="Read-only access to workflows and execution history",
        permissions={
            Permission.WORKFLOW_READ,
            Permission.EXECUTION_VIEW,
            Permission.EXECUTION_LOGS,
            Permission.AUDIT_READ,
        },
        max_concurrent_executions=0,
        max_execution_duration_minutes=0,
    ),
    PredefinedRole.OPERATOR: RoleDefinition(
        name="Operator",
        description="Execute workflows and monitor executions",
        permissions={
            Permission.WORKFLOW_READ,
            Permission.WORKFLOW_EXECUTE,
            Permission.WORKFLOW_STOP,
            Permission.EXECUTION_VIEW,
            Permission.EXECUTION_LOGS,
            Permission.POLICY_READ,
        },
        max_concurrent_executions=5,
        max_execution_duration_minutes=30,
    ),
    PredefinedRole.DEVELOPER: RoleDefinition(
        name="Developer",
        description="Create and modify workflows",
        permissions={
            Permission.WORKFLOW_CREATE,
            Permission.WORKFLOW_READ,
            Permission.WORKFLOW_UPDATE,
            Permission.WORKFLOW_EXECUTE,
            Permission.WORKFLOW_STOP,
            Permission.EXECUTION_VIEW,
            Permission.EXECUTION_LOGS,
            Permission.POLICY_READ,
            Permission.SECRETS_READ,
        },
        max_concurrent_executions=10,
        max_execution_duration_minutes=60,
    ),
    PredefinedRole.SECURITY_ADMIN: RoleDefinition(
        name="Security Admin",
        description="Manage policies, audit logs, and security settings",
        permissions={
            Permission.POLICY_READ,
            Permission.POLICY_CREATE,
            Permission.POLICY_UPDATE,
            Permission.POLICY_DELETE,
            Permission.AUDIT_READ,
            Permission.AUDIT_EXPORT,
            Permission.SECRETS_READ,
            Permission.SECRETS_WRITE,
            Permission.WORKFLOW_READ,
            Permission.EXECUTION_VIEW,
        },
        max_concurrent_executions=0,
        max_execution_duration_minutes=0,
    ),
    PredefinedRole.SYSTEM_ADMIN: RoleDefinition(
        name="System Administrator",
        description="Full system access and administration",
        permissions=set(Permission),  # All permissions
        max_concurrent_executions=100,
        max_execution_duration_minutes=1440,  # 24 hours
    ),
}


@dataclass
class User:
    """User entity with roles and permissions"""
    user_id: str
    username: str
    email: str
    roles: Set[PredefinedRole] = field(default_factory=set)
    custom_permissions: Set[Permission] = field(default_factory=set)
    is_active: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = None
    mfa_enabled: bool = False
    mfa_secret: Optional[str] = None
    
    def get_all_permissions(self) -> Set[Permission]:
        """Aggregate permissions from all roles"""
        perms = set(self.custom_permissions)
        for role_name in self.roles:
            if role_name in DEFAULT_ROLES:
                perms.update(DEFAULT_ROLES[role_name].permissions)
        return perms
    
    def has_permission(self, perm: Permission) -> bool:
        """Check if user has specific permission"""
        return perm in self.get_all_permissions()
    
    def has_any_permission(self, perms: List[Permission]) -> bool:
        """Check if user has any of the permissions"""
        return any(self.has_permission(p) for p in perms)
    
    def has_all_permissions(self, perms: List[Permission]) -> bool:
        """Check if user has all permissions"""
        return all(self.has_permission(p) for p in perms)


@dataclass
class ServiceAccount:
    """Service account for API access and automation"""
    account_id: str
    name: str
    roles: Set[PredefinedRole] = field(default_factory=set)
    api_key: str = ""
    api_key_hash: str = ""  # bcrypt hash of key
    is_active: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_used: Optional[datetime] = None
    allowed_origins: List[str] = field(default_factory=list)
    rate_limit: int = 1000  # Requests per hour
    
    def get_all_permissions(self) -> Set[Permission]:
        """Get all permissions for this service account"""
        perms = set()
        for role_name in self.roles:
            if role_name in DEFAULT_ROLES:
                perms.update(DEFAULT_ROLES[role_name].permissions)
        return perms


class AccessContext:
    """Request-level access context"""
    
    def __init__(self, user: Optional[User] = None, service_account: Optional[ServiceAccount] = None,
                 ip_address: str = "", user_agent: str = ""):
        self.user = user
        self.service_account = service_account
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.timestamp = datetime.utcnow()
        self.request_id = self._generate_request_id()
    
    @staticmethod
    def _generate_request_id() -> str:
        import uuid
        return str(uuid.uuid4())
    
    def get_identity(self) -> str:
        """Get identity string for audit logging"""
        if self.user:
            return f"user:{self.user.username}"
        elif self.service_account:
            return f"service:{self.service_account.name}"
        return "unknown"
    
    def get_permissions(self) -> Set[Permission]:
        """Get all permissions for this context"""
        if self.user:
            return self.user.get_all_permissions()
        elif self.service_account:
            return self.service_account.get_all_permissions()
        return set()


class RBACEngine:
    """RBAC enforcement engine"""
    
    def __init__(self):
        self.users: Dict[str, User] = {}
        self.service_accounts: Dict[str, ServiceAccount] = {}
        self.roles: Dict[str, RoleDefinition] = dict(DEFAULT_ROLES)
    
    def create_user(self, user_id: str, username: str, email: str, 
                    roles: Optional[List[PredefinedRole]] = None) -> User:
        """Create new user"""
        if user_id in self.users:
            raise ValueError(f"User {user_id} already exists")
        
        user = User(
            user_id=user_id,
            username=username,
            email=email,
            roles=set(roles or [PredefinedRole.VIEWER])
        )
        self.users[user_id] = user
        logger.info(f"Created user {username} with roles {user.roles}")
        return user
    
    def create_service_account(self, account_id: str, name: str,
                              roles: Optional[List[PredefinedRole]] = None) -> Tuple[ServiceAccount, str]:
        """Create new service account and return API key"""
        if account_id in self.service_accounts:
            raise ValueError(f"Service account {account_id} already exists")
        
        import secrets
        import hashlib
        
        # Generate API key
        api_key = secrets.token_urlsafe(32)
        api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        account = ServiceAccount(
            account_id=account_id,
            name=name,
            roles=set(roles or [PredefinedRole.VIEWER]),
            api_key_hash=api_key_hash
        )
        self.service_accounts[account_id] = account
        logger.info(f"Created service account {name}")
        return account, api_key  # Return unhashed key only once
    
    def verify_permission(self, ctx: AccessContext, required_perm: Permission) -> Tuple[bool, Optional[str]]:
        """Verify if context has required permission"""
        perms = ctx.get_permissions()
        
        if required_perm not in perms:
            reason = f"Permission denied: {required_perm} required"
            logger.warning(f"[{ctx.request_id}] {ctx.get_identity()} - {reason}")
            return False, reason
        
        return True, None
    
    def verify_any_permission(self, ctx: AccessContext, required_perms: List[Permission]) -> Tuple[bool, Optional[str]]:
        """Verify if context has any of the required permissions"""
        perms = ctx.get_permissions()
        
        if not any(p in perms for p in required_perms):
            reason = f"Permission denied: one of {required_perms} required"
            logger.warning(f"[{ctx.request_id}] {ctx.get_identity()} - {reason}")
            return False, reason
        
        return True, None
    
    def verify_all_permissions(self, ctx: AccessContext, required_perms: List[Permission]) -> Tuple[bool, Optional[str]]:
        """Verify if context has all required permissions"""
        perms = ctx.get_permissions()
        
        missing = [p for p in required_perms if p not in perms]
        if missing:
            reason = f"Permission denied: {missing} required"
            logger.warning(f"[{ctx.request_id}] {ctx.get_identity()} - {reason}")
            return False, reason
        
        return True, None
    
    def grant_role(self, user_id: str, role: PredefinedRole) -> bool:
        """Grant role to user"""
        if user_id not in self.users:
            return False
        
        self.users[user_id].roles.add(role)
        logger.info(f"Granted role {role} to user {user_id}")
        return True
    
    def revoke_role(self, user_id: str, role: PredefinedRole) -> bool:
        """Revoke role from user"""
        if user_id not in self.users:
            return False
        
        self.users[user_id].roles.discard(role)
        logger.info(f"Revoked role {role} from user {user_id}")
        return True
    
    def deactivate_user(self, user_id: str) -> bool:
        """Deactivate user account"""
        if user_id not in self.users:
            return False
        
        self.users[user_id].is_active = False
        logger.warning(f"Deactivated user {user_id}")
        return True
    
    def check_user_active(self, user: User) -> Tuple[bool, Optional[str]]:
        """Check if user is active"""
        if not user.is_active:
            return False, "User account is deactivated"
        return True, None


class RBACDecorator:
    """Decorator for requiring permissions on functions"""
    
    def __init__(self, rbac_engine: RBACEngine, required_perms: List[Permission], require_all: bool = False):
        self.rbac_engine = rbac_engine
        self.required_perms = required_perms
        self.require_all = require_all
    
    def __call__(self, func):
        def wrapper(ctx: AccessContext, *args, **kwargs):
            # Check permissions
            if self.require_all:
                allowed, reason = self.rbac_engine.verify_all_permissions(ctx, self.required_perms)
            else:
                allowed, reason = self.rbac_engine.verify_any_permission(ctx, self.required_perms)
            
            if not allowed:
                raise PermissionError(reason)
            
            # Proceed with function
            return func(ctx, *args, **kwargs)
        
        return wrapper


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    rbac = RBACEngine()
    
    # Create users
    user1 = rbac.create_user("u1", "alice", "alice@example.com", [PredefinedRole.OPERATOR])
    user2 = rbac.create_user("u2", "bob", "bob@example.com", [PredefinedRole.DEVELOPER])
    
    # Create service account
    sa, key = rbac.create_service_account("sa1", "automation", [PredefinedRole.OPERATOR])
    
    # Test permissions
    ctx1 = AccessContext(user=user1, ip_address="192.168.1.1")
    allowed, reason = rbac.verify_permission(ctx1, Permission.WORKFLOW_EXECUTE)
    print(f"Alice can execute: {allowed}")
    
    allowed, reason = rbac.verify_permission(ctx1, Permission.WORKFLOW_DELETE)
    print(f"Alice can delete: {allowed} ({reason})")
    
    # Service account context
    ctx2 = AccessContext(service_account=sa)
    allowed, reason = rbac.verify_permission(ctx2, Permission.WORKFLOW_EXECUTE)
    print(f"Service account can execute: {allowed}")
