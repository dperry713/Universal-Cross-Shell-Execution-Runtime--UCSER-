from pydantic import BaseModel, Field
from typing import List, Optional, Union, Literal, Any

class WriteFileIntent(BaseModel):
    intent: Literal["write_file"]
    path: str
    content: str

class ReadFileIntent(BaseModel):
    intent: Literal["read_file"]
    path: str

class ExecuteCommandIntent(BaseModel):
    intent: Literal["execute_command"]
    command: str
    arguments: List[str] = Field(default_factory=list)

class NetworkRequestIntent(BaseModel):
    intent: Literal["network_request"]
    url: str
    method: str = "GET"
    payload: Optional[str] = None

ExecutionIntent = Union[WriteFileIntent, ReadFileIntent, ExecuteCommandIntent, NetworkRequestIntent]

class UCERIntentDSL(BaseModel):
    """
    Formal DSL for UCER intents, enabling static analysis and verification.
    """
    command_id: str
    intents: List[ExecutionIntent]
