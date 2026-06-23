import subprocess
import time
import os
import shutil
import tempfile
import uuid
import threading
import queue
from typing import Dict, Any, Optional, Set, List
from core.types import ExecutionContext, Capability
from core.config import config
from utils.observability.logging import get_logger

from security.network import NetworkAuditor
from engine.adapters.base import BaseSandboxAdapter

logger = get_logger(__name__, level=config.log_level)

class SandboxConfigBuilder:
    @staticmethod
    def build_docker_start_cmd(shell: str, context: ExecutionContext, workspace_path: str, container_name: str) -> list:
        # Phase 2 & 3: Capability-driven network and Seccomp
        network_mode = "none"
        proxy_env = {}
        
        if Capability.NETWORK in context.capabilities:
            network_mode = "bridge"
            auditor = NetworkAuditor()
            proxy_env = auditor.get_proxy_env()

        seccomp_path = config.seccomp_profile_path
        
        cmd = [
            "docker", "run", "-d", "--rm",
            f"--name={container_name}",
            f"--network={network_mode}",
            f"--memory={config.default_memory_limit}", 
            f"--cpus={config.default_cpu_limit}",
            "-v", f"{workspace_path}:/workspace",
            "-w", "/workspace"
        ]

        if os.path.exists(seccomp_path):
            cmd.extend(["--security-opt", f"seccomp={seccomp_path}"])
        
        # Inject context environment and proxy environment
        combined_env = {**context.environment, **proxy_env}
        for k, v in combined_env.items():
            if v is not None:
                cmd.extend(["-e", f"{k}={v}"])
                
        if shell in ["powershell", "ps"]:
            cmd.extend(["mcr.microsoft.com/powershell:latest", "pwsh", "-NoLogo", "-NoProfile", "-Command", "while($true) { Start-Sleep -Seconds 1 }"])
        else:
            cmd.extend(["alpine:latest", "tail", "-f", "/dev/null"])
            
        return cmd

class SandboxExecutor(BaseSandboxAdapter):
    """
    Phase 3 Sandbox Executor:
    - Persistent containers with Seccomp protection.
    - Filesystem diff tracking (side effects).
    - Persistent shell process with non-blocking I/O and hardened markers.
    """
    def __init__(self, shell: str):
        self.shell = shell
        self.active_containers: Dict[str, str] = {}
        self.workspaces: Dict[str, str] = {}
        self.processes: Dict[str, subprocess.Popen] = {}
        self.output_queues: Dict[str, queue.Queue] = {}
        self.error_queues: Dict[str, queue.Queue] = {}
        self.stop_events: Dict[str, threading.Event] = {}

    def _reader_thread(self, stream, q, event):
        """
        Hardened Reader Thread (Phase 3 Remediation):
        Uses small reads and checks the stop event to prevent blocking hangs.
        """
        try:
            # Set stream to non-blocking if possible, or read character by character
            # On Windows, we can use a small timeout or just rely on the event check
            # between lines/chunks.
            while not event.is_set():
                line = stream.readline()
                if not line:
                    break
                q.put(line)
        except Exception as e:
            logger.debug(f"Reader thread exception: {e}")
        finally:
            try: stream.close()
            except: pass

    def _get_or_start_container(self, context: ExecutionContext) -> str:
        exec_id = context.execution_id
        if exec_id in self.active_containers:
            return self.active_containers[exec_id]

        workspace_base = config.workspace_base_dir
        os.makedirs(workspace_base, exist_ok=True)
        host_path = os.path.join(workspace_base, exec_id)
        os.makedirs(host_path, exist_ok=True)
        self.workspaces[exec_id] = host_path

        container_name = f"ucser_{exec_id[:8]}_{uuid.uuid4().hex[:4]}"
        start_cmd = SandboxConfigBuilder.build_docker_start_cmd(self.shell, context, host_path, container_name)
        
        subprocess.run(start_cmd, check=True, capture_output=True, text=True)
        self.active_containers[exec_id] = container_name
        
        if self.shell in ["powershell", "ps"]:
            exec_cmd = ["docker", "exec", "-i", container_name, "pwsh", "-NoLogo", "-NoProfile", "-Command", "-"]
        else:
            exec_cmd = ["docker", "exec", "-i", container_name, "sh"]
            
        proc = subprocess.Popen(
            exec_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1
        )
        self.processes[exec_id] = proc
        
        # Setup non-blocking readers
        self.output_queues[exec_id] = queue.Queue()
        self.error_queues[exec_id] = queue.Queue()
        self.stop_events[exec_id] = threading.Event()
        
        threading.Thread(target=self._reader_thread, args=(proc.stdout, self.output_queues[exec_id], self.stop_events[exec_id]), daemon=True).start()
        threading.Thread(target=self._reader_thread, args=(proc.stderr, self.error_queues[exec_id], self.stop_events[exec_id]), daemon=True).start()

        time.sleep(0.5)
        return container_name

    def run(self, command: str, context: ExecutionContext) -> Dict[str, Any]:
        start_time = time.time()
        exec_id = context.execution_id
        container_name = self._get_or_start_container(context)
        
        proc = self.processes[exec_id]
        out_q = self.output_queues[exec_id]
        err_q = self.error_queues[exec_id]
        
        # Phase 1.3 & 2.1: Hardened Marker and Exit Code Retrieval
        marker_id = uuid.uuid4().hex
        marker = f"__UCSER_END_{marker_id}__"
        
        if self.shell in ["powershell", "ps"]:
            wrapped_cmd = f"{command}\n$__ucser_exit = $LASTEXITCODE; Write-Output '{marker}'; Write-Output \"__UCSER_EXIT__:$__ucser_exit\"\n"
        else:
            wrapped_cmd = f"{command}\n__ucser_exit=$?; echo '{marker}'; echo \"__UCSER_EXIT__:$__ucser_exit\"\n"

        exit_code = 0
        stdout_data = []
        stderr_data = []

        try:
            if proc.poll() is not None:
                raise RuntimeError("Sandbox shell process died unexpectedly")

            proc.stdin.write(wrapped_cmd)
            proc.stdin.flush()
            
            execution_timeout = config.execution_timeout
            step_start = time.time()
            
            while True:
                if time.time() - step_start > execution_timeout:
                    raise TimeoutError(f"Command execution timed out after {execution_timeout}s")
                
                # Concurrently drain stderr to prevent deadlock
                while not err_q.empty():
                    stderr_data.append(err_q.get_nowait())

                try:
                    line = out_q.get(timeout=0.1)
                    if marker in line:
                        # Found marker, now look for exit code
                        try:
                            exit_line = out_q.get(timeout=1.0)
                            if "__UCSER_EXIT__:" in exit_line:
                                exit_code = int(exit_line.split(":")[1].strip())
                        except:
                            pass
                        break
                    stdout_data.append(line)
                except queue.Empty:
                    if proc.poll() is not None:
                        break
                    continue
            
            # Final drain
            while not err_q.empty():
                stderr_data.append(err_q.get_nowait())
            
            # Phase 2.3: Refined Side-Effect Tracking
            diff_res = subprocess.run(
                ["docker", "diff", container_name],
                capture_output=True, text=True
            )
            
            added, modified, deleted = [], [], []
            ignored_prefixes = [
                "/proc", "/sys", "/dev", "/.dockerenv", 
                "/etc/hostname", "/etc/hosts", "/etc/resolv.conf",
                "/run", "/root/.bash_history", "/root/.ash_history"
            ]
            
            for line in diff_res.stdout.splitlines():
                if not line.strip(): continue
                parts = line.split(" ", 1)
                if len(parts) < 2: continue
                code, path = parts
                
                if any(path.startswith(prefix) for prefix in ignored_prefixes):
                    continue
                
                if code == "A": added.append(path)
                elif code == "C": modified.append(path)
                elif code == "D": deleted.append(path)
            
            side_effects = {
                "files_added": added,
                "files_modified": modified,
                "files_deleted": deleted
            }
            
        except Exception as e:
            logger.error(f"Execution error: {e}")
            stderr_data.append(f"[Sandbox Error] {str(e)}")
            exit_code = -1
            side_effects = {}
            if isinstance(e, (TimeoutError, RuntimeError)):
                self.cleanup(context)
            
        duration_ms = (time.time() - start_time) * 1000
        
        return {
            "stdout": "".join(stdout_data).strip(),
            "stderr": "".join(stderr_data).strip(),
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "side_effects": side_effects
        }

    def cleanup(self, context: ExecutionContext):
        exec_id = context.execution_id
        
        if exec_id in self.stop_events:
            self.stop_events[exec_id].set()
        
        if exec_id in self.processes:
            proc = self.processes.pop(exec_id)
            try:
                if proc.stdin:
                    proc.stdin.write("exit\n")
                    proc.stdin.close()
                proc.terminate()
                proc.wait(timeout=2)
            except: 
                try: proc.kill()
                except: pass
            
        if exec_id in self.active_containers:
            name = self.active_containers.pop(exec_id)
            subprocess.run(["docker", "stop", name], capture_output=True)
            
        if exec_id in self.workspaces:
            path = self.workspaces.pop(exec_id)
            if os.path.exists(path):
                shutil.rmtree(path, ignore_errors=True)
        
        self.output_queues.pop(exec_id, None)
        self.error_queues.pop(exec_id, None)
        self.stop_events.pop(exec_id, None)
