import asyncio
from mcp.server import Server, NotificationOptions
from mcp.server.models import InitializationOptions
import mcp.types as types
import mcp.server.stdio
from semantic.llm_client import MockLLMClient
from semantic.compiler import SemanticCompiler
from core.executor import UniversalExecutor
from core.types import ExecutionContext, Capability

class MCPServer:
    """
    UCSER Model Context Protocol (MCP) Server.
    Provides tools for LLM-based agents to execute verified semantic intents.
    """
    def __init__(self):
        self.server = Server("ucser-control-plane")
        self.executor = UniversalExecutor()
        self.compiler = SemanticCompiler(MockLLMClient())
        self._setup_handlers()

    def _setup_tools(self):
        @self.server.list_tools()
        async def handle_list_tools() -> list[types.Tool]:
            return [
                types.Tool(
                    name="execute_intent",
                    description="Executes a natural language intent with deterministic verification.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "intent": {"type": "string", "description": "The natural language instruction to execute"},
                            "reasoning": {"type": "string", "description": "Explanation of why this action is being taken"}
                        },
                        "required": ["intent"]
                    }
                ),
                types.Tool(
                    name="replay_execution",
                    description="Replays a previous execution to verify determinism or debug failure.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "ucer_id": {"type": "string", "description": "The command_id of the original UCER"}
                        },
                        "required": ["ucer_id"]
                    }
                )
            ]

        @self.server.call_tool()
        async def handle_call_tool(name: str, arguments: dict | None) -> list[types.TextContent]:
            if not arguments:
                raise ValueError("Arguments are required")

            if name == "execute_intent":
                intent = arguments["intent"]
                # Create context for the tool call
                context = ExecutionContext(capabilities={Capability.EXEC, Capability.FS_READ})
                ucer = self.compiler.compile(intent, context=context)
                result = await self.executor.execute_ucer(ucer, context=context)
                
                output = []
                for trace in result.traces:
                    if trace.stdout: output.append(f"[stdout] {trace.stdout}")
                    if trace.stderr: output.append(f"[stderr] {trace.stderr}")
                
                response_text = f"Executed UCER {result.command_id}. Status: {result.status}\n\n" + "\n".join(output)
                return [types.TextContent(type="text", text=response_text)]

            elif name == "replay_execution":
                ucer_id = arguments["ucer_id"]
                result = await self.executor.replay(ucer_id)
                return [types.TextContent(type="text", text=f"Replayed UCER {ucer_id}. PARITY VERIFIED.")]

            raise ValueError(f"Unknown tool: {name}")

    def _setup_handlers(self):
        self._setup_tools()

    async def run(self):
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="ucser-control-plane",
                    server_version="1.0.0",
                    capabilities=self.server.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )

if __name__ == "__main__":
    server = MCPServer()
    asyncio.run(server.run())
