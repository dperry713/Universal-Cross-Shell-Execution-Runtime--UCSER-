import uuid
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional, Literal, Set
from datetime import datetime
from core.types import Capability
from core.uck import UCKCore
from utils.cryptography import sign_payload, verify_signature

class ExecutionStep(BaseModel):
    step_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    adapter: Literal["bash", "powershell", "ps", "linux", "python", "microvm"]
    command: str
    expected_state_changes: Optional[Dict[str, Any]] = None

class ExecutionTrace(BaseModel):
    step_id: str
    adapter: str
    command: str
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: float
    side_effects: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.now)

class UCER(BaseModel):
    """Universal Cross-Execution Record with Cryptographic Trust Chain"""
    command_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    intent: str
    steps: List[ExecutionStep]
    
    # Enriched post-execution
    traces: List[ExecutionTrace] = Field(default_factory=list)
    required_capabilities: Set[Capability] = Field(default_factory=set)
    state_hash: Optional[str] = None
    status: str = "pending" # pending, running, completed, failed

    # Phase 5: Cryptographic Trust Chain
    canonical_hash: Optional[str] = None
    control_signature: Optional[str] = None
    execution_signature: Optional[str] = None
    execution_pub_key: Optional[str] = None

    def get_canonical_hash(self) -> str:
        """
        Computes the immutable hash of the intent and steps.
        Utilizes uCK-Hash (UCSER Core-Kernel) for low-level optimization.
        """
        return UCKCore.compute_canonical_hash_uck(self.model_dump_canonical())

    def sign_intent(self, private_key_pem: bytes):
        """Signs the canonical hash of the intent using the Control Plane private key."""
        self.canonical_hash = self.get_canonical_hash()
        self.control_signature = sign_payload(private_key_pem, self.canonical_hash)

    def verify_integrity(self, public_key_pem: bytes) -> bool:
        """Verifies that the current UCER state matches the signed Control Plane intent."""
        if not self.control_signature or not self.canonical_hash:
            return False
        
        # Verify hash matches current content
        if self.get_canonical_hash() != self.canonical_hash:
            return False
            
        # Verify signature matches hash
        return verify_signature(public_key_pem, self.canonical_hash, self.control_signature)

    def model_dump_canonical(self) -> dict:
        """Returns a dict suitable for canonical hashing (no signatures/hash/mutable data included)."""
        data = self.model_dump(exclude={
            'canonical_hash', 'control_signature', 'execution_signature', 
            'execution_pub_key', 'traces', 'status', 'timestamp'
        })
        # Convert sets to sorted lists for consistent JSON serialization
        if 'required_capabilities' in data:
            data['required_capabilities'] = sorted([cap.value for cap in data['required_capabilities']])
        return data
