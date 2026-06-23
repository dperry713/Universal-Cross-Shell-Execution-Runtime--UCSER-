from core.executor import UniversalExecutor
import json

def main():
    ex = UniversalExecutor()
    cmd = "ps:Get-ChildItem C:/ | ForEach-Object { $_.Name }"
    print(f"Executing: {cmd}")
    count = 0
    for item in ex.execute(cmd):
        count += 1
        if count <= 3:
            print(f"ITEM {count}: {item}")
    print(f"Total items: {count}")
    ex.close()

if __name__ == "__main__":
    main()
