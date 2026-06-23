import sys
import os

# Add the project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.executor import UniversalExecutor

def main():
    engine = UniversalExecutor()

    print("Universal Cross-Shell Runtime (Phase 3.1 - Robust Streaming)")

    try:
        while True:
            try:
                cmd = input("> ")
            except EOFError:
                break

            if cmd in ["exit", "quit"]:
                break

            if not cmd.strip():
                continue

            # Execute returns a generator
            try:
                for item in engine.execute(cmd):
                    # Real-time output emission
                    if isinstance(item, dict):
                        stream = item.get('stream', 'stdout')
                        data = item.get('data', item)
                        if stream == 'error':
                            print(f"\033[91m[Error]\033[0m {data}")
                        elif stream == 'warning':
                            print(f"\033[93m[Warning]\033[0m {data}")
                        elif stream == 'stderr':
                            print(f"\033[91m[Stderr]\033[0m {data}")
                        else:
                            print(data, end='')
                print()
            except Exception as e:
                print(f"Execution Error: {e}")
                print(f"\033[91m[Runtime Error]\033[0m {e}")
    finally:
        engine.close()

if __name__ == "__main__":
    main()
