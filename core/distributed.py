from typing import Dict, Any, List
from core.types import ExecutionContext, Capability

from core.config import config
from utils.observability.logging import get_logger

logger = get_logger(__name__, level=config.log_level)

class DistributedNodeManager:
    """
    Advanced Node Orchestrator for UCSER.
    Negotiates isolation levels (Docker vs. MicroVM) based on intent risk.
    """
    def __init__(self):
        # In a production system, this would be backed by a Node Registry / NATS KV Store
        self.nodes = [
            {"id": "worker-L1-01", "type": "docker", "status": "online", "load": 0.1},
            {"id": "worker-L1-02", "type": "docker", "status": "online", "load": 0.5},
            {"id": "worker-L2-01", "type": "microvm", "status": "online", "load": 0.0}
        ]
        
    def negotiate_isolation(self, ucer: Any) -> str:
        """
        Determines the required isolation level based on capabilities.
        High-risk capabilities (DELETE_ROOT, NETWORK) trigger MicroVM isolation.
        """
        high_risk = {Capability.DELETE_ROOT, Capability.NETWORK}
        ucer_caps = set(ucer.required_capabilities)
        
        if ucer_caps.intersection(high_risk):
            return "microvm"
        return "docker"

    def allocate_node(self, required_isolation: str) -> str:
        """Finds the least-loaded available node for the requested isolation."""
        eligible = [n for n in self.nodes if n["type"] == required_isolation and n["status"] == "online"]
        if not eligible:
            raise RuntimeError(f"No available nodes for isolation level: {required_isolation}")
            
        # Sort by load
        selected = sorted(eligible, key=lambda x: x["load"])[0]
        return selected["id"]
        
    def dispatch(self, node_id: str, shell: str, command: str, context: ExecutionContext) -> Dict[str, Any]:
        """
        Sends the execution context and command over gRPC/REST to the remote node.
        Mocks the network dispatch for Phase 4 scaffolding.
        """
        logger.info("Dispatching task to remote node", extra={"node_id": node_id, "shell": shell, "command": command[:50]})
        
        # Mock Response
        return {
            "stdout": f"[Distributed Execution on {node_id}]\n__UCSER_END_MOCK__",
            "stderr": "",
            "exit_code": 0,
            "duration_ms": 150.0,
            "side_effects": {"files_added": [], "files_removed": []}
        }
