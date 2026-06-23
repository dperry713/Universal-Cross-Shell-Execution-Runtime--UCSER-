import asyncio
import json
import uuid
import time
from typing import Dict, Any, Optional
from core.ucer import UCER
from core.types import ExecutionContext
from core.scheduler import JobScheduler
from core.dag import UCERGraph, DAGNode
from semantic.compiler import SemanticCompiler
from semantic.llm_client import MockLLMClient

from core.config import config
from utils.observability.logging import get_logger

logger = get_logger(__name__, level=config.log_level)

class DistributedOrchestrator:
    """
    Control Plane Orchestrator for NATS-based distributed execution.
    Integrates with JobScheduler for high-availability dispatching.
    """
    def __init__(self, scheduler: Optional[JobScheduler] = None):
        self.scheduler = scheduler or JobScheduler(nats_url=config.nats_url)

    async def dispatch_ucer(self, ucer: UCER, context: ExecutionContext, priority: int = 1):
        """
        Submits the UCER to the high-availability Job Queue.
        """
        logger.info("Orchestrator dispatching UCER", extra={"command_id": ucer.command_id})
        
        # Ensure we are connected
        if not self.scheduler.nc:
            await self.scheduler.connect()
            
        seq = await self.scheduler.submit_job(ucer, context, priority=priority)
        
        return {
            "status": "dispatched",
            "sequence": seq,
            "stream": "UCSER_JOBS",
            "command_id": ucer.command_id
        }

    async def get_execution_status(self, ucer_id: str) -> str:
        """
        Queries the distributed state for job status.
        (Future Phase: Integration with NATS KV Store)
        """
        return "dispatched"

class DAGOrchestrator:
    """
    Phase 13/Iteration 2: Autonomous DAG Orchestrator with Self-Healing Recovery.
    Manages state and topology of a UCERGraph using reactive event-driven orchestration
    and NATS KV-based persistent synchronization.
    """
    def __init__(self, orchestrator: DistributedOrchestrator, compiler: SemanticCompiler, db=None):
        self.orchestrator = orchestrator
        self.compiler = compiler
        self.db = db # This should be a NATSDatabase for Iteration 2
        self._node_updated = asyncio.Condition()

    async def _sync_graph_state(self, graph: UCERGraph):
        """Persists the current DAG state to distributed consensus (NATS KV)."""
        if self.db and hasattr(self.db, "set_kv"):
            await self.db.set_kv(f"graph.{graph.graph_id}", graph.model_dump_json())
            logger.info(f"DAG State Synced to KV: {graph.graph_id}")

    async def recover_graph(self, graph_id: str) -> Optional[UCERGraph]:
        """Recovers a DAG from distributed state to resume execution."""
        if self.db and hasattr(self.db, "get_kv"):
            raw = await self.db.get_kv(f"graph.{graph_id}")
            if raw:
                return UCERGraph.model_validate_json(raw)
        return None

    async def _on_job_event(self, event: Dict[str, Any], graph: UCERGraph):
        """Callback for DataBus events to advance the DAG state."""
        ucer_id = event.get("ucer_id")
        success = event.get("success", False)
        
        for node in graph.nodes.values():
            if node.ucer_id == ucer_id:
                if success:
                    graph.mark_completed(node.node_id, ucer_id)
                else:
                    graph.mark_failed(node.node_id)
                
                # Persistence Checkpoint for Recovery
                await self._sync_graph_state(graph)
                
                async with self._node_updated:
                    self._node_updated.notify_all()
                break

    async def execute_graph(self, graph: UCERGraph, context: ExecutionContext) -> bool:
        """
        Reactive execution loop for a topological workflow.
        Advances only when dependencies are satisfied or events are received.
        """
        logger.info(f"Starting Reactive DAG Orchestration for graph {graph.graph_id}: {graph.goal}")
        
        # Initial State Checkpoint
        await self._sync_graph_state(graph)

        databus = getattr(self.orchestrator.scheduler, "databus", None)
        if databus:
            await databus.subscribe(
                "telemetry.execution", 
                lambda ev: self._on_job_event(ev, graph)
            )

        while not graph.is_complete() and not graph.has_failed():
            ready_nodes = graph.get_ready_nodes()
            
            if not ready_nodes:
                async with self._node_updated:
                    await asyncio.wait_for(self._node_updated.wait(), timeout=30.0)
                continue

            for node in ready_nodes:
                node.status = "running"
                logger.info(f"Dispatching Node: {node.name} ({node.node_id})")
                
                try:
                    ucer = self.compiler.compile(node.intent, context=context)
                    node.ucer_id = ucer.command_id
                    
                    await self.orchestrator.dispatch_ucer(ucer, context)
                    
                    # Update state after dispatch
                    await self._sync_graph_state(graph)
                    
                    if not databus:
                         graph.mark_completed(node.node_id, ucer.command_id)
                         await self._sync_graph_state(graph)
                         async with self._node_updated:
                             self._node_updated.notify_all()
                    
                except Exception as e:
                    logger.error(f"Node Dispatch Failed {node.name}: {e}")
                    graph.mark_failed(node.node_id)
                    await self._sync_graph_state(graph)
                    async with self._node_updated:
                        self._node_updated.notify_all()
                    break
                
        return not graph.has_failed()
