import sys
import os

# Add parent directory to path so we can import semantic
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from semantic.llm_client import BlacklistedAIProxyClient

def main():
    print("Testing BlacklistedAIProxy Connection...")
    client = BlacklistedAIProxyClient()
    
    # Test connection state
    is_connected = client.check_connection()
    if is_connected:
        print("[SUCCESS] Proxy is reachable at http://localhost:3000")
        
        print("\nTesting intent translation (generation)...")
        try:
            ucer = client.to_ucer("Find all python files modified today")
            print("[SUCCESS] Successfully translated intent to UCER JSON:")
            print(ucer)
        except Exception as e:
            print(f"[ERROR] Generation failed: {e}")
    else:
        print("[ERROR] Could not connect to Proxy at http://localhost:3000")
        print("Please ensure the proxy is running via 'npm start' in tests/BlacklistedAIProxy.")

if __name__ == "__main__":
    main()
