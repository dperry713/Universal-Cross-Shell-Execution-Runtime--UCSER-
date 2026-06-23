import sys
import os
import time

# Add the project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.executor import UniversalExecutorFacade as UniversalExecutor
from core.ucer import UCER, ExecutionStep

def run_test(engine, command, label):
    print(f"[{label}] Executing: {command}")
    start = time.time()
    
    # Parse shell and command
    if ":" in command:
        shell, cmd = command.split(":", 1)
    else:
        shell, cmd = "ps", command

    # Create a UCER with a single step
    ucer = UCER(
        intent=label,
        steps=[ExecutionStep(adapter=shell, command=cmd)]
    )
    
    try:
        # execute_ucer returns the updated UCER with traces
        result_ucer = engine.execute_ucer(ucer)
        results = result_ucer.traces
    except Exception as e:
        print(f"Error during execution: {e}")
        results = []
        
    end = time.time()
    
    # Simplify output for readability
    simplified = []
    for trace in results:
        simplified.append(f"[stdout] {trace.stdout}")
        if trace.stderr:
            simplified.append(f"[stderr] {trace.stderr}")
    print(f"Result: {simplified}")
    print(f"Time: {end - start:.4f}s")
    print("-" * 20)
    return results

def main():
    engine = UniversalExecutor()

    print("=== Phase 3.1 Verification: Security Gate & Adversary Payloads ===")

    # 1. Base Security Check (Safe command)
    run_test(engine, "ps:Get-Date", "Security 1 (Safe PS)")

    # 2. Adversary Payload: Risky Cmdlet
    # This should be blocked by the auditor
    run_test(engine, "ps:Invoke-WebRequest http://malicious.com", "Security 2 (Risky Cmdlet)")

    # 3. Adversary Payload: Obfuscation
    # This simulates an encoded command often used in attacks
    encoded_evil = "JHBlID0gJ2hlbGxvJzsgaWV4ICRwZQ==" # 'hello'; iex $pe
    run_test(engine, f"ps:'{encoded_evil}'", "Security 3 (Obfuscation Check)")

    # 4. Adversary Payload: Dynamic Execution (IEX)
    run_test(engine, "ps:iex 'Get-Date'", "Security 4 (IEX Block)")

    # 5. Bash check (Bypassing security gate? No, it only audits PS for now)
    run_test(engine, "bash:echo hello", "Security 5 (Bash Baseline)")

    engine.close()
    print("Verification Complete.")

if __name__ == "__main__":
    main()
