import sys
import os
import time
import base64

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.executor import UniversalExecutor
from core.ir import SemanticBridge

def main():
    executor = UniversalExecutor()
    bridge = SemanticBridge(executor)

    print("=== Phase 3.2 Verification: Experience Moat ===")

    # 1. Test Universal Path Resolver & Semantic Delete/List
    print("[1] Testing Universal LS (Windows - Drive Root)...")
    results = list(bridge.list_dir("C:/"))
    print(f"Result (C:/): {len(results)} items found")
    if len(results) == 0:
        print(f"Full results (C:/): {results}")

    print("[2] Testing Universal LS (Windows - Subdir)...")
    # Using a path that definitely exists and has content
    user_path = "C:/Users"
    results = list(bridge.list_dir(user_path))
    print(f"Result ({user_path}): {len(results)} items found")
    for r in results[:3]: print(f"  - {r}")

    print("[3] Testing Universal LS (Linux)...")
    results = list(bridge.list_dir("/tmp"))
    print(f"Result (/tmp): {len(results)} items found")

    # 2. Test Cross-Boundary Bridge (Windows -> Linux)
    print("[4] Testing Memory Bridge: Windows -> Linux...")
    test_file = os.path.abspath("bridge_test.txt")
    with open(test_file, "w") as f:
        f.write("CROSS-BOUNDARY DATA: HELLO FROM WINDOWS")
    
    linux_dest = "/tmp/bridge_test.txt"
    results = list(bridge.copy(test_file, linux_dest))
    print(f"Bridge Copy Result: {results}")

    # Verify Linux side
    print("[5] Verifying Linux side...")
    verify = list(executor.execute(f"bash:cat {linux_dest}"))
    print(f"Linux Content: {verify}")

    # 3. Test Reverse Cross-Boundary Bridge (Linux -> Windows)
    print("[6] Testing Memory Bridge: Linux -> Windows...")
    win_dest = os.path.abspath("reverse_bridge_test.txt")
    results = list(bridge.copy(linux_dest, win_dest))
    print(f"Reverse Bridge Result: {results}")

    if os.path.exists(win_dest):
        with open(win_dest, "r") as f:
            print(f"Windows Content: {f.read()}")
        os.remove(win_dest)
    
    os.remove(test_file)
    executor.close()
    print("Verification Complete.")

if __name__ == "__main__":
    main()
