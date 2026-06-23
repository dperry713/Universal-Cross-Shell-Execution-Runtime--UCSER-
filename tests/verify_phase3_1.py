import sys
import os
import time

# Add the project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.executor import UniversalExecutor

def run_test(engine, command, label):
    print(f"[{label}] Executing: {command}")
    start = time.time()
    
    # engine.execute is now a generator
    results = []
    try:
        for item in engine.execute(command):
            results.append(item)
    except Exception as e:
        print(f"Error during execution: {e}")
        
    end = time.time()
    
    # Simplify output for readability
    simplified = []
    for item in results:
        if isinstance(item, dict):
            # Extract stream info
            stream = item.get('stream', 'unknown')
            data = item.get('data', item)
            simplified.append(f"[{stream}] {data}")
        else:
            simplified.append(str(item))
    print(f"Result: {simplified}")
    print(f"Time: {end - start:.4f}s")
    print("-" * 20)
    return results

def main():
    engine = UniversalExecutor()

    print("=== Phase 3.1 Verification: Robustness, Errors, and Delta Sync ===")

    # 1. Security & Quoting Hardening (Base64 Transport)
    run_test(engine, "ps:Write-Output \"It's a 'complex' quoting `\"test`\"\"", "Security 1 (PS Quotes)")

    # 2. Rich Error Handling
    run_test(engine, "ps:Get-InvalidCommand", "Error 1 (PS Invalid Cmd)")
    run_test(engine, "bash:ls /nonexistent_path_ucser", "Error 2 (Bash Invalid Path)")

    # 3. Delta Variable Synchronization (Bidirectional)
    run_test(engine, "bash:export UCSER_SYNC_VAR='from_bash'", "Sync 1 (Bash Set)")
    run_test(engine, "ps:$env:UCSER_SYNC_VAR", "Sync 2 (PS Check)")
    run_test(engine, "ps:$env:UCSER_SYNC_VAR = 'updated_in_ps'", "Sync 3 (PS Update)")
    run_test(engine, "bash:echo $UCSER_SYNC_VAR", "Sync 4 (Bash Check)")

    # 4. Multi-stream capture (Warnings)
    run_test(engine, "ps:Write-Warning 'This is a warning'", "Stream 1 (PS Warning)")

    # 5. End-to-End Streaming Pipe (Real Test)
    # This test pipes objects through stages
    run_test(engine, "ps:1..3 | ps:ForEach-Object { $_ * 2 } | bash:grep 4", "Streaming 1 (PS -> PS -> Bash)")

    engine.close()
    print("Verification Complete.")

if __name__ == "__main__":
    main()
