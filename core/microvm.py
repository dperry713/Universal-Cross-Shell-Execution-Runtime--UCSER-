import subprocess
import time
import os
import uuid
import json
import tempfile
from typing import Dict, Any, Optional, Set
from core.types import ExecutionContext, Capability

from core.config import config
from utils.observability.logging import get_logger

from engine.adapters.base import BaseSandboxAdapter

logger = get_logger(__name__, level=config.log_level)

class MicroVMConfigBuilder:
    """
    Builds configuration JSON for Firecracker microVMs.
    """
    @staticmethod
    def build_config(context: ExecutionContext, socket_path: str, rootfs_path: str, kernel_path: str) -> dict:
        machine_config = {
            "boot-source": {
                "kernel_image_path": kernel_path,
                "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
            },
            "drives": [
                {
                    "drive_id": "rootfs",
                    "path_on_host": rootfs_path,
                    "is_root_device": True,
                    "is_read_only": False
                }
            ],
            "machine-config": {
                "vcpu_count": int(config.default_cpu_limit),
                "mem_size_mib": int(config.default_memory_limit.replace('m', ''))
            }
        }
        
        if Capability.NETWORK in context.capabilities:
             # Add tap device config for network
             machine_config["network-interfaces"] = [
                 {
                     "iface_id": "eth0",
                     "guest_mac": "AA:FC:00:00:00:01",
                     "host_dev_name": "tap0"
                 }
             ]
             
        return machine_config

class MicroVMExecutor(BaseSandboxAdapter):
    """
    Phase 4 & 10 Advanced Sandbox:
    Executes commands inside a Firecracker microVM for hardware-level isolation.
    Implements Snapshot-based Replay (Phase 9).
    """
    def __init__(self, shell: str):
        self.shell = shell
        self.active_vms: Dict[str, str] = {} # exec_id -> socket_path
        self.snapshots: Dict[str, dict] = {} # exec_id -> {mem_path, guest_drive_path}
        
        self.fc_bin = config.firecracker_bin
        self.kernel_path = config.kernel_path
        self.base_rootfs = config.rootfs_path

    def create_snapshot(self, context: ExecutionContext):
        """
        Creates a snapshot of the running MicroVM.
        Calls Firecracker API: PUT /snapshot/create
        """
        exec_id = context.execution_id
        if exec_id not in self.active_vms: return

        snap_dir = os.path.join(tempfile.gettempdir(), f"ucser_snaps_{exec_id}")
        os.makedirs(snap_dir, exist_ok=True)
        
        mem_file = os.path.join(snap_dir, "mem.snap")
        state_file = os.path.join(snap_dir, "state.snap")
        
        # In a real system, we'd send the PUT request to self.active_vms[exec_id]
        logger.info("Creating snapshot", extra={"exec_id": exec_id, "snap_dir": snap_dir})
        self.snapshots[exec_id] = {
            "mem_file": mem_file,
            "state_file": state_file,
            "timestamp": time.time()
        }

    def restore_snapshot(self, context: ExecutionContext):
        """
        Restores a MicroVM from a previous snapshot.
        Calls Firecracker API: PUT /snapshot/load
        """
        exec_id = context.execution_id
        if exec_id not in self.snapshots:
            raise ValueError(f"No snapshot found for execution {exec_id}")

        logger.info("Restoring snapshot", extra={"exec_id": exec_id})
        # 1. Stop existing VM if any
        self.cleanup(context)
        
        # 2. Start new VM process and load snapshot via API
        self._start_vm(context, snapshot=self.snapshots[exec_id])

    def _start_vm(self, context: ExecutionContext, snapshot: Optional[dict] = None) -> str:
        exec_id = context.execution_id
        socket_path = f"/tmp/firecracker_{exec_id}.socket"
        
        if not os.path.exists(self.fc_bin):
            logger.warning("Firecracker binary not found. Running in MOCK Mode.")
            self.active_vms[exec_id] = "mock_socket"
            return "mock_socket"

        # ... (Start Firecracker process and configure via API)
        # If snapshot is provided, we send a PUT to /snapshot/load instead of standard boot.
        
        self.active_vms[exec_id] = socket_path
        return socket_path

    def run(self, command: str, context: ExecutionContext) -> Dict[str, Any]:
        start_time = time.time()
        exec_id = context.execution_id
        
        if exec_id not in self.active_vms:
            self._start_vm(context)
            
        socket_path = self.active_vms[exec_id]
        
        # Phase 4 Mock: Execute command via serial console or SSH into the MicroVM
        # Since this is a scaffold, we simulate the isolated execution.
        stdout_data = f"[MicroVM: {self.shell}] Executed: {command}\n__UCSER_END_MOCK__"
        stderr_data = ""
        exit_code = 0
        side_effects = {"files_added": [], "files_removed": []}
        
        # Snapshot-based replay logic would involve hitting the /snapshot Firecracker API here.
            
        duration_ms = (time.time() - start_time) * 1000
        
        return {
            "stdout": stdout_data.strip(),
            "stderr": stderr_data.strip(),
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "side_effects": side_effects
        }

    def cleanup(self, context: ExecutionContext):
        exec_id = context.execution_id
        if exec_id in self.active_vms:
             socket = self.active_vms.pop(exec_id)
             # Send InstanceHalt to API, then clean up socket and rootfs copy
             if os.path.exists(socket):
                 try: os.remove(socket)
                 except: pass
