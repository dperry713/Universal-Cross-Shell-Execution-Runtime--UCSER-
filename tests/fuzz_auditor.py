import random
import string
from security.auditor import PowerShellAuditor

def generate_random_command(length=10):
    chars = string.ascii_letters + string.digits + " `~!@#$%^&*()-_=+[{]}\\|;:'\",<.>/? "
    return "".join(random.choice(chars) for _ in range(length))

def main():
    auditor = PowerShellAuditor()
    print("Starting PowerShell Auditor Fuzzer...")
    
    blocked_count = 0
    parsed_count = 0
    error_count = 0
    
    for i in range(100):
        cmd = generate_random_command(random.randint(5, 50))
        try:
            ast = auditor.parse(cmd)
            parsed_count += 1
            if ast.findings:
                blocked_count += 1
        except Exception as e:
            print(f"Fuzzer error on command '{cmd}': {e}")
            error_count += 1
            
    auditor.cleanup()
    print(f"Fuzzing Complete.")
    print(f"Total commands: 100")
    print(f"Successfully parsed: {parsed_count}")
    print(f"Commands with security findings: {blocked_count}")
    print(f"Unexpected errors: {error_count}")

if __name__ == '__main__':
    main()
