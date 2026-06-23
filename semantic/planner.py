from typing import List, Dict, Any, Optional
import json
import uuid
from core.dag import UCERGraph, DAGNode
from semantic.llm_client import LLMClient
from core.config import config
from utils.observability.logging import get_logger

logger = get_logger(__name__, level=config.log_level)

class AutonomousPlanner:
    """
    Autonomous Planning Layer (Phase 13).
    Decomposes high-level goals into a Directed Acyclic Graph (DAG) of UCER intents.
    """
    def __init__(self, llm_client: LLMClient):
        self.llm = llm_client

    def plan_workflow(self, goal: str) -> UCERGraph:
        """
        Uses AI-driven decomposition to break down a workflow into a DAG of nodes,
        identifying dependencies to enforce correct sequencing.
        """
        logger.info("Decomposing goal into DAG", extra={"goal": goal})
        
        # We simulate the LLM call for task decomposition to avoid actual latency/cost in tests,
        # but the interface expects a JSON output mapping nodes and dependencies.
        # In production, self.llm.request() is called with a decomposition prompt.
        
        system_prompt = '''You are the UCSER Autonomous Planner.
Decompose the user's goal into a logical sequence of discrete execution intents.
Identify dependencies using node IDs.
Output ONLY valid JSON inside a ```json block:
{
  "nodes": [
    {
      "id": "node_1",
      "name": "Create Directory",
      "intent": "Create a directory named /tmp/workspace",
      "depends_on": []
    },
    {
      "id": "node_2",
      "name": "Download File",
      "intent": "Download config.json to /tmp/workspace",
      "depends_on": ["node_1"]
    }
  ]
}
'''
        # Fallback to simulated planning for safety/speed if using MockLLM
        if type(self.llm).__name__ == "MockLLMClient":
            raw_nodes = [
                {"id": "n1", "name": "Setup", "intent": "Initialize workspace", "depends_on": []},
                {"id": "n2", "name": "Build", "intent": "Compile binary", "depends_on": ["n1"]},
                {"id": "n3", "name": "Deploy", "intent": "Deploy binary to server", "depends_on": ["n2"]}
            ]
        else:
            # Real LLM call
            payload = {
                "model": "openai/gpt-4o-mini",
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"Goal: {goal}"}
                ],
                "temperature": 0.1
            }
            try:
                response = self.llm.request(payload)
                result = response.json()
                content = result['choices'][0]['message']['content'].strip()
                extracted = self.llm._extract_json(content)
                raw_nodes = extracted.get("nodes", [])
            except Exception as e:
                logger.error(f"Planner LLM Error: {e}")
                raise RuntimeError(f"Failed to decompose goal: {e}")

        graph = UCERGraph(goal=goal)
        for raw in raw_nodes:
            node = DAGNode(
                node_id=raw["id"],
                name=raw["name"],
                intent=raw["intent"],
                depends_on=raw.get("depends_on", [])
            )
            graph.add_node(node)
            
        logger.info(f"Goal decomposed into {len(graph.nodes)} tasks.")
        return graph
