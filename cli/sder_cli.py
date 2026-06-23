import argparse
import sys
import json
import asyncio
from semantic.llm_client import MockLLMClient, BlacklistedAIProxyClient
from semantic.compiler import SemanticCompiler
from core.executor import UniversalExecutor
from core.orchestrator import DistributedOrchestrator
from core.types import ExecutionContext, Capability
from core.config import config

def print_ucer(ucer):
    print(f"\n[UCER ID: {ucer.command_id}] Status: {ucer.status}")
    print(f"Intent: {ucer.intent}")
    print(f"Required Capabilities: {[c.value for c in ucer.required_capabilities]}")
    for trace in ucer.traces:
        print(f"\n--- Step: {trace.step_id} ({trace.adapter}) ---")
        print(f"Command: {trace.command}")
        print(f"Exit Code: {trace.exit_code}")
        if trace.stdout:
            print(f"Stdout:\n{trace.stdout}")

async def run_cli():
    parser = argparse.ArgumentParser(description="UCSER - Universal Cross-Shell Execution Runtime")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Execute intent
    exec_parser = subparsers.add_parser("exec", help="Execute a semantic intent")
    exec_parser.add_argument("intent", help="Natural language instruction")
    exec_parser.add_argument("--local", action="store_true", help="Execute locally instead of distributed")
    exec_parser.add_argument("--caps", nargs="+", help="Explicit capabilities (comma separated)")

    # Replay
    replay_parser = subparsers.add_parser("replay", help="Replay a previous UCER")
    replay_parser.add_argument("ucer_id", help="The command_id to replay")

    # List
    subparsers.add_parser("list", help="List recent execution records")

    args = parser.parse_args()

    executor = UniversalExecutor()
    orchestrator = DistributedOrchestrator()
    # Use real proxy if key available, else mock
    llm = BlacklistedAIProxyClient() if config.llm_api_token else MockLLMClient()
    compiler = SemanticCompiler(llm)

    try:
        if args.command == "exec":
            caps = {Capability(c) for c in args.caps} if args.caps else {Capability.EXEC, Capability.FS_READ}
            context = ExecutionContext(capabilities=caps)
            
            print(f"Compiling: {args.intent}")
            ucer = compiler.compile(args.intent, context=context)
            
            if args.local:
                print("Executing locally...")
                result = await executor.execute_ucer(ucer, context=context)
                print_ucer(result)
            else:
                print("Dispatching to distributed queue...")
                res = await orchestrator.dispatch_ucer(ucer, context)
                print(f"Job dispatched. Sequence: {res['sequence']}")

        elif args.command == "replay":
            print(f"Replaying: {args.ucer_id}")
            result = await executor.replay(args.ucer_id)
            print_ucer(result)

        elif args.command == "list":
            records = await executor.db.list_ucers(limit=10)
            print(f"\n{'COMMAND_ID':<40} | {'STATUS':<10} | {'INTENT'}")
            print("-" * 75)
            for r in records:
                print(f"{r.command_id:<40} | {r.status:<10} | {r.intent}")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        await orchestrator.scheduler.close()

if __name__ == "__main__":
    asyncio.run(run_cli())
