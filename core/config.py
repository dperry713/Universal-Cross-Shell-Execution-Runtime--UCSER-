from pydantic import BaseModel, Field
from typing import Optional
import os

class UCSERConfig(BaseModel):
    """
    Centralized configuration for UCSER.
    """
    # Security
    cp_private_key_path: str = os.getenv("UCSER_CP_PRIVATE_KEY", "cp_private.pem")
    cp_public_key_path: str = os.getenv("UCSER_CP_PUBLIC_KEY", "cp_public.pem")
    seccomp_profile_path: str = os.getenv("UCSER_SECCOMP_PATH", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "security", "seccomp_profile.json")))

    # Execution
    execution_timeout: int = int(os.getenv("UCSER_EXECUTION_TIMEOUT", "30"))
    default_memory_limit: str = os.getenv("UCSER_MEMORY_LIMIT", "512m")
    default_cpu_limit: float = float(os.getenv("UCSER_CPU_LIMIT", "1.0"))
    workspace_base_dir: str = os.getenv("UCSER_WORKSPACE_BASE", os.path.join(os.environ.get("TEMP", "/tmp"), "ucser_workspaces"))

    # Firecracker / MicroVM
    firecracker_bin: str = os.getenv("UCSER_FC_BIN", "/usr/bin/firecracker")
    kernel_path: str = os.getenv("UCSER_KERNEL_PATH", "/var/lib/firecracker/vmlinux")
    rootfs_path: str = os.getenv("UCSER_ROOTFS_PATH", "/var/lib/firecracker/rootfs.ext4")

    # Semantic / Backup
    backup_base_dir: str = os.getenv("UCSER_BACKUP_BASE", os.path.join(os.environ.get("TEMP", "/tmp"), "ucser_backups"))

    # Orchestration
    nats_url: str = os.getenv("UCSER_NATS_URL", "nats://127.0.0.1:4222")
    llm_api_token: str = os.getenv("LLM_API_TOKEN", "")

    # Observability
    log_level: str = os.getenv("UCSER_LOG_LEVEL", "INFO")
    db_path: str = os.getenv("UCSER_DB_PATH", "sder.db")

# Singleton instance
config = UCSERConfig()
