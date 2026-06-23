import subprocess
import shutil
import os

def run_bash(command: str, input_text=None):
    # Dynamic path discovery (Phase 3 Remediation)
    bash_path = shutil.which("bash")
    if not bash_path:
        # Check common Windows locations if which fails (e.g. Git Bash)
        common_paths = [
            r"C:\Program Files\Git\bin\bash.exe",
            r"C:\Program Files\Git\usr\bin\bash.exe",
            r"C:\msys64\usr\bin\bash.exe"
        ]
        for p in common_paths:
            if os.path.exists(p):
                bash_path = p
                break
    
    if not bash_path:
        raise RuntimeError("Bash executable not found in system path. Please ensure Git Bash or MSYS2 is installed.")

    # HARD GUARANTEE: string only
    if input_text is None:
        input_text = ""

    # Pass input_text via stdin for robustness
    if input_text:
        result = subprocess.run(
            [bash_path, "-c", command],
            input=input_text,
            text=True,
            capture_output=True
        )
    else:
        result = subprocess.run(
            [bash_path, "-c", command],
            text=True,
            capture_output=True
        )

    return [
        {"type": "text", "data": line}
        for line in result.stdout.splitlines()
        if line.strip()
    ]
