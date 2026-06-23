import subprocess
import json
import sys
import os

from core.config import config
from utils.observability.logging import get_logger

logger = get_logger(__name__, level=config.log_level)

# Get the path to the wrapper script relative to this file
WRAPPER_PATH = os.path.join(os.path.dirname(__file__), "ps_wrapper.ps1")

def safe_serialize(input_data):
    if input_data is None:
        return ""

    # FORCE STRICT JSON ONLY
    try:
        if isinstance(input_data, list):
            # NDJSON: one JSON object per line
            return "\n".join(json.dumps(x, ensure_ascii=False) for x in input_data)
        return json.dumps(input_data, ensure_ascii=False)
    except Exception:
        try:
            return json.dumps({"value": str(input_data)}, ensure_ascii=False)
        except:
            return ""

def run_powershell(command: str, input_data=None):
    ndjson = safe_serialize(input_data)

    # Call the standalone wrapper script
    proc = subprocess.Popen(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", WRAPPER_PATH, "-command", command],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    stdout, stderr = proc.communicate(input=ndjson)

    if stderr.strip():
        logger.error("PowerShell Error", extra={"stderr": stderr.strip()})

    lines = [l.strip() for l in stdout.splitlines() if l.strip()]

    if not lines:
        return []

    parsed = []
    for line in lines:
        try:
            parsed.append(json.loads(line))
        except:
            parsed.append({"type": "raw", "data": line})

    return parsed
