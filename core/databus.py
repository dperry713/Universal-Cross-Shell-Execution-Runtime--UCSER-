import nats
import json
import asyncio
from typing import Dict, Any, Callable, Optional
from core.config import config
from utils.observability.logging import get_logger

logger = get_logger(__name__, level=config.log_level)

class UnifiedDataBus:
    """
    Asynchronous message bus for cross-process communication in UCSER.
    Leverages NATS JetStream for reliable pub/sub and state broadcast.
    """
    def __init__(self, nats_url: Optional[str] = None):
        self.nats_url = nats_url or config.nats_url
        self.nc = None
        self.js = None

    async def connect(self):
        """Initializes NATS and JetStream connection."""
        self.nc = await nats.connect(self.nats_url)
        self.js = self.nc.jetstream()
        logger.info(f"Unified Data Bus connected to {self.nats_url}")

    async def publish_event(self, subject: str, data: Dict[str, Any]):
        """Broadcasts a structured event to the bus."""
        if not self.js: await self.connect()
        
        payload = json.dumps(data).encode('utf-8')
        await self.js.publish(subject, payload)
        logger.debug(f"Event published to {subject}")

    async def subscribe(self, subject: str, callback: Callable, durable: Optional[str] = None):
        """
        Subscribes to a subject.
        If 'durable' is provided, JetStream will ensure message delivery across restarts.
        """
        if not self.js: await self.connect()
        
        sub = await self.js.subscribe(subject, durable=durable)
        logger.info(f"Subscribed to {subject} (Durable: {durable})")
        
        async def listen():
            try:
                async for msg in sub.messages:
                    try:
                        data = json.loads(msg.data.decode())
                        await callback(data)
                        await msg.ack()
                    except Exception as e:
                        logger.error(f"Data Bus callback error on {subject}: {e}")
                        await msg.nak()
            except Exception as e:
                logger.error(f"Data Bus subscription loop error on {subject}: {e}")

        # In a real system, we'd manage these tasks via a Registry
        asyncio.create_task(listen())

    async def close(self):
        if self.nc:
            await self.nc.close()
            logger.info("Unified Data Bus disconnected")
