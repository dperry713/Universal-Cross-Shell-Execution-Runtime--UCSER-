import pytest
import asyncio
from semantic.planner import AutonomousPlanner
from semantic.llm_client import MockLLMClient
from core.orchestrator import DistributedOrchestrator, DAGOrchestrator
from core.dag import UCERGraph, DAGNode
from semantic.compiler import SemanticCompilerFacade
from core.types import ExecutionContext, Capability
from unittest.mock import AsyncMock

@pytest.mark.asyncio
async def test_autonomous_planner_decomposition():
    llm = MockLLMClient()
    planner = AutonomousPlanner(llm)
    
    goal = "Build and deploy the application"
    graph = planner.plan_workflow(goal)
    
    assert isinstance(graph, UCERGraph)
    assert graph.goal == goal
    assert len(graph.nodes) == 3
    
    # Check dependencies mapped correctly
    assert "n1" in graph.nodes
    assert len(graph.nodes["n1"].depends_on) == 0
    assert "n1" in graph.nodes["n2"].depends_on
    assert "n2" in graph.nodes["n3"].depends_on

@pytest.mark.asyncio
async def test_dag_orchestration():
    mock_orchestrator = DistributedOrchestrator()
    mock_orchestrator.dispatch_ucer = AsyncMock(return_value={"status": "dispatched", "sequence": 1})
    
    compiler = SemanticCompilerFacade(MockLLMClient())
    dag_orchestrator = DAGOrchestrator(mock_orchestrator, compiler)
    
    # Create a mock graph: A -> B, A -> C
    graph = UCERGraph(goal="Test Graph")
    graph.add_node(DAGNode(node_id="A", name="Task A", intent="Echo A"))
    graph.add_node(DAGNode(node_id="B", name="Task B", intent="Echo B", depends_on=["A"]))
    graph.add_node(DAGNode(node_id="C", name="Task C", intent="Echo C", depends_on=["A"]))
    
    context = ExecutionContext(capabilities={Capability.EXEC})
    
    success = await dag_orchestrator.execute_graph(graph, context)
    
    assert success is True
    assert graph.is_complete() is True
    assert mock_orchestrator.dispatch_ucer.call_count == 3
    
@pytest.mark.asyncio
async def test_dag_security_enforcement():
    mock_orchestrator = DistributedOrchestrator()
    mock_orchestrator.dispatch_ucer = AsyncMock()
    
    mock_llm = MockLLMClient()
    from unittest.mock import MagicMock
    mock_llm.to_ucer = MagicMock(return_value={
        "command_id": "malicious-id",
        "intent": "delete root",
        "steps": [{"step_id": "1", "adapter": "bash", "command": "rm -rf /"}]
    })
    
    compiler = SemanticCompilerFacade(mock_llm)
    dag_orchestrator = DAGOrchestrator(mock_orchestrator, compiler)
    
    # Task requires DELETE_ROOT
    graph = UCERGraph(goal="Malicious Graph")
    graph.add_node(DAGNode(node_id="A", name="Task A", intent="delete root"))
    
    # Context does NOT have network capability
    context = ExecutionContext(capabilities={Capability.EXEC})
    
    # The SemanticCompiler will fail capability discovery/policy evaluation
    success = await dag_orchestrator.execute_graph(graph, context)
    
    assert success is False
    assert graph.has_failed() is True
    assert mock_orchestrator.dispatch_ucer.call_count == 0
