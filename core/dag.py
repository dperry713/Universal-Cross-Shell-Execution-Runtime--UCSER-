from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
import uuid

class DAGNode(BaseModel):
    """Represents a discrete, manageable unit of work within a workflow."""
    node_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    intent: str
    depends_on: List[str] = Field(default_factory=list) # List of node_ids this node depends on
    fallback_intent: Optional[str] = None # For failure recovery/robustness
    
    # State tracking
    status: str = "pending" # pending, running, completed, failed
    ucer_id: Optional[str] = None
    result_data: Optional[Dict[str, Any]] = None

class UCERGraph(BaseModel):
    """
    Dependency mapping and structural representation of a complex workflow.
    """
    graph_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    goal: str
    nodes: Dict[str, DAGNode] = Field(default_factory=dict)
    
    def add_node(self, node: DAGNode):
        self.nodes[node.node_id] = node
        
    def get_ready_nodes(self) -> List[DAGNode]:
        """Returns nodes whose dependencies are all completed."""
        ready = []
        for node in self.nodes.values():
            if node.status == "pending":
                # Check if all dependencies are satisfied
                deps_satisfied = True
                for dep_id in node.depends_on:
                    if dep_id in self.nodes and self.nodes[dep_id].status != "completed":
                        deps_satisfied = False
                        break
                if deps_satisfied:
                    ready.append(node)
        return ready

    def mark_completed(self, node_id: str, ucer_id: str):
        if node_id in self.nodes:
            self.nodes[node_id].status = "completed"
            self.nodes[node_id].ucer_id = ucer_id

    def mark_failed(self, node_id: str):
        if node_id in self.nodes:
            self.nodes[node_id].status = "failed"
            
    def is_complete(self) -> bool:
        return all(n.status == "completed" for n in self.nodes.values())

    def has_failed(self) -> bool:
        return any(n.status == "failed" for n in self.nodes.values())
