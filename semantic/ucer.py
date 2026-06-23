from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
import uuid
from core.types import Capability

class ExecutionStep(BaseModel):
    """A discrete, atomic shell operation."""
    step_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    shell: str  # e.g., 'powershell', 'bash', 'python'
    command: str
    timeout_ms: int = 30000
    ignore_errors: bool = False

class RollbackStrategy(BaseModel):
    """Defines how to revert a semantic operation if it fails."""
    enabled: bool = False
    steps: List[ExecutionStep] = Field(default_factory=list)

class ExpectedOutput(BaseModel):
    """Defines the shape and assertions for the expected output."""
    format: str = "text" # e.g., 'json', 'text', 'binary'
    contains: Optional[List[str]] = None
    not_contains: Optional[List[str]] = None

class UCER(BaseModel):
    """
    Universal Command Execution Representation.
    The single source of truth for any operation executing in the UCSER kernel.
    """
    command_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    intent: str
    required_capabilities: List[Capability] = Field(default_factory=list)
    execution_steps: List[ExecutionStep] = Field(default_factory=list)
    expected_outputs: Optional[ExpectedOutput] = None
    rollback_strategy: Optional[RollbackStrategy] = None
    
    # Metadata for execution tracking and paging
    metadata: Dict[str, Any] = Field(default_factory=dict)
