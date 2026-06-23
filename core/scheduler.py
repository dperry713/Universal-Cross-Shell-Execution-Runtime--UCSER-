import nats
import json
import uuid
import time
import asyncio
from typing import Dict, Any, Optional, List
from nats.js.errors import BadRequestError
from core.ucer import UCER
from core.types import ExecutionContext
from core.config import config
from utils.observability.logging import get_logger

logger = get_logger(__name__, level=config.log_level)

class JobScheduler:
    """
    High-Availability Job Scheduler for UCSER.
    Handles job queuing via NATS JetStream and worker load balancing.
    """
    def __init__(self, nats_url: str = "nats://localhost:4222"):
        self.nats_url = nats_url
        self.nc = None
        self.js = None

    async def connect(self):
        """Connects to NATS and initializes JetStream."""
        self.nc = await nats.connect(self.nats_url)
        self.js = self.nc.jetstream()
        
        # Ensure the UCSER stream exists
        try:
            await self.js.add_stream(name="UCSER_JOBS", subjects=["ucser.jobs.*"])
            logger.info("JetStream UCSER_JOBS initialized")
        except BadRequestError:
            # Stream likely already exists
            pass

    async def submit_job(self, ucer: UCER, context: ExecutionContext, priority: int = 1):
        """
        Submits a UCER job to the distributed queue.
        Uses canonical serialization to ensure JSON compatibility.
        """
        if not self.js:
            await self.connect()

        payload = {
            "ucer": ucer.model_dump_canonical(),
            "context": context.snapshot(),
            "meta": {
                "priority": priority,
                "submitted_at": time.time(),
                "trace_id": str(uuid.uuid4())
            }
        }
        
        subject = f"ucser.jobs.{ucer.command_id}"
        ack = await self.js.publish(subject, json.dumps(payload).encode('utf-8'))
        logger.info("Job submitted to distributed queue", extra={
            "command_id": ucer.command_id,
            "stream": ack.stream,
            "seq": ack.seq
        })
        return ack.seq

    async def close(self):
        if self.nc:
            await self.nc.close()

class DistributedWorker:
    """
    Worker node implementation that pulls jobs from JetStream.
    """
    def __init__(self, worker_id: str, nats_url: str = "nats://localhost:4222"):
        self.worker_id = worker_id
        self.nats_url = nats_url
        self.nc = None
        self.js = None

    async def start(self, callback):
        """Starts the worker loop, pulling jobs from the queue."""
        if not self.js:
            self.nc = await nats.connect(self.nats_url)
            self.js = self.nc.jetstream()
        
        # Durable consumer to ensure jobs aren't lost on worker failure
        sub = await self.js.subscribe("ucser.jobs.*", durable=f"worker-{self.worker_id}")
        logger.info(f"Worker {self.worker_id} listening for jobs...")

        try:
            while True:
                msg = await sub.next_msg(timeout=None)
                data = json.loads(msg.data.decode())
                logger.info(f"Worker {self.worker_id} processing job {data['ucer']['command_id']}")
                
                try:
                    await callback(data)
                    await msg.ack()
                except Exception as e:
                    logger.error(f"Worker processing error: {e}")
                    # Negative ack to allow retry on another node
                    await msg.nak()
                
                # Yield to event loop
                await asyncio.sleep(0)
        except Exception as e:
            logger.error(f"Worker sub loop error: {e}")
        finally:
            if self.nc:
                await self.nc.close()
