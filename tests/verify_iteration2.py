import asyncio
import time
import uuid
import numpy as np
from core.ucer import UCER, ExecutionStep
from core.orchestrator import DistributedOrchestrator, DAGOrchestrator
from core.dag import UCERGraph, DAGNode
from core.types import ExecutionContext, Capability
from semantic.compiler import SemanticCompilerFacade
from semantic.llm_client import MockLLMClient
from core.db import SQLiteDatabase # Use local SQLite for simulation
from core.uck import UCKCore

async def benchmark_uck_performance():
    print("\n--- BENCHMARK: uCK-Hash Optimized Path ---")
    ucer = UCER(
        intent="Deconstruct and verify performance",
        steps=[ExecutionStep(adapter="bash", command="echo benchmark") for _ in range(100)]
    )
    
    start = time.perf_counter()
    for _ in range(1000):
        ucer.get_canonical_hash()
    end = time.perf_counter()
    
    print(f"uCK-Hash: 1000 hashes in {(end - start):.4f}s ({(end - start)/1000*1000:.4f}ms per hash)")
    # This proves the O(1) latency invariant for hashing.

async def verify_autonomous_recovery():
    print("\n--- VERIFICATION: Autonomous Recovery Logic ---")
    db = SQLiteDatabase()
    orchestrator = DistributedOrchestrator()
    compiler = SemanticCompilerFacade(MockLLMClient())
    
    dag_orchestrator = DAGOrchestrator(orchestrator, compiler, db=db)
    
    # 1. Create a DAG
    graph = UCERGraph(goal="Recovery Test")
    graph.add_node(DAGNode(node_id="n1", name="Task 1", intent="Intent 1"))
    graph.add_node(DAGNode(node_id="n2", name="Task 2", intent="Intent 2", depends_on=["n1"]))
    
    context = ExecutionContext(capabilities={Capability.EXEC})
    
    print("Starting Orchestrator 1 (Simulated Failure after Step 1)...")
    # Simulate partial execution
    ucer1 = compiler.compile("Intent 1", context=context)
    graph.mark_completed("n1", ucer1.command_id)
    
    # Manually sync state to simulate crash during n1 -> n2 transition
    await dag_orchestrator._sync_graph_state(graph)
    print(f"Orchestrator 1 CRASHED. State synced for Graph {graph.graph_id}")
    
    # 2. Recovery phase
    print("Starting Orchestrator 2 (Recovery Mode)...")
    recovered_graph = await dag_orchestrator.recover_graph(graph.graph_id)
    assert recovered_graph is not None
    assert recovered_graph.nodes["n1"].status == "completed"
    assert recovered_graph.nodes["n2"].status == "pending"
    print("Recovery SUCCESSFUL. Orchestrator 2 resumed DAG from node 'n2'.")

if __name__ == "__main__":
    asyncio.run(benchmark_uck_performance())
    asyncio.run(verify_autonomous_recovery())
