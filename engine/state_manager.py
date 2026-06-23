import os
import shutil
import hashlib
import logging
import platform
from typing import Dict, Optional

class SnapshotManager:
    """Base class for state snapshots."""
    def capture(self): raise NotImplementedError
    def restore(self): raise NotImplementedError
    def cleanup(self): raise NotImplementedError

class FastHardlinkSnapshot(SnapshotManager):
    """
    Simulates CoW performance using OS hardlinks. 
    Reduces I/O significantly as file data is not copied.
    """
    def __init__(self, root_dir: str):
        self.root_dir = root_dir
        self.backup_path = f"{root_dir}_snapshot_{hashlib.md5(root_dir.encode()).hexdigest()}"
        self.env_snapshot = dict(os.environ)

    def capture(self):
        if os.path.exists(self.backup_path):
            shutil.rmtree(self.backup_path)
            
        # Use hardlinks for O(1) space and fast I/O
        # cp -al is the standard way on Linux. On Windows we fallback to copytree.
        if platform.system() != "Windows":
             import subprocess
             subprocess.run(["cp", "-al", self.root_dir, self.backup_path], check=True)
        else:
             shutil.copytree(self.root_dir, self.backup_path, dirs_exist_ok=True)

    def restore(self):
        if os.path.exists(self.backup_path):
            shutil.rmtree(self.root_dir)
            shutil.copytree(self.backup_path, self.root_dir, dirs_exist_ok=True)
        os.environ.clear()
        os.environ.update(self.env_snapshot)

    def cleanup(self):
        if os.path.exists(self.backup_path):
            shutil.rmtree(self.backup_path)

class StateSnapshot(FastHardlinkSnapshot):
    """
    Compatibility wrapper for existing StateSnapshot usage.
    """
    def __init__(self, root_dir: str):
        super().__init__(root_dir)
        self.fs_hash = self._calculate_fs_hash()

    def _calculate_fs_hash(self) -> str:
        hasher = hashlib.sha256()
        ignore_exts = {'.log', '.db', '.pyc', '.tmp'}
        ignore_dirs = {'node_modules', '.git', '__pycache__', '.pytest_cache', 'venv'}
        
        for root, dirs, files in os.walk(self.root_dir):
            dirs[:] = [d for d in dirs if d not in ignore_dirs and not d.startswith('_backup_')]
            for name in sorted(files):
                if any(name.endswith(ext) for ext in ignore_exts): continue
                filepath = os.path.join(root, name)
                hasher.update(name.encode())
                try:
                    with open(filepath, 'rb') as f:
                        while chunk := f.read(8192): hasher.update(chunk)
                except: continue
        return hasher.hexdigest()

    def capture_backup(self): self.capture()
