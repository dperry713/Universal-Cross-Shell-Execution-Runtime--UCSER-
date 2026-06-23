import re
import os
import base64
from core.config import config

class SecurityError(RuntimeError):
    """Raised when a sandbox escape is detected."""
    pass

def resolve_os_from_path(path: str) -> str:
    """
    Heuristic to determine if a path belongs to Windows or Linux.
    """
    if not path: return "UNKNOWN"
    
    # Path Normalization: Convert / to \ for Windows drives
    if re.match(r'^[a-zA-Z]:', path):
        return "WINDOWS"
    
    if path.startswith('\\\\'):
        return "WINDOWS"
    
    if path.startswith('/'):
        return "LINUX"
        
    return "UNKNOWN"

def _validate_path(path: str):
    """
    Strictly validates that a path is within the allowed workspace.
    Implements Phase 2 Remediation: Sandbox Escape protection.
    """
    if not path:
        return
    
    abs_path = os.path.abspath(path)
    # Ensure workspace_base_dir is also absolute for comparison
    base_dir = os.path.abspath(config.workspace_base_dir)
    
    if not abs_path.startswith(base_dir):
        raise SecurityError(f"Sandbox escape detected! Path '{abs_path}' is outside workspace '{base_dir}'")

class SemanticBridge:
    def __init__(self, executor):
        self.executor = executor

    def delete(self, path: str):
        _validate_path(path)
        target_os = resolve_os_from_path(path)
        if target_os == "WINDOWS":
            win_path = path.replace('/', '\\')
            return self.executor.execute(f"ps:Remove-Item -Path '{win_path}' -Recurse -Force")
        elif target_os == "LINUX":
            return self.executor.execute(f"bash:rm -rf '{path}'")
        else:
            return [{"type": "error", "data": f"Cannot resolve OS for path: {path}", "stream": "resolver"}]

    def list_dir(self, path: str):
        _validate_path(path)
        target_os = resolve_os_from_path(path)
        if target_os == "WINDOWS":
            win_path = path.replace('/', '\\')
            # Ensure path ends with slash for drive root
            if re.match(r'^[a-zA-Z]:$', win_path): win_path += '\\'
            return self.executor.execute(f"ps:Get-ChildItem -Path '{win_path}' -Force | Select-Object Name, Length, LastWriteTime, Mode")
        elif target_os == "LINUX":
            return self.executor.execute(f"bash:ls -la '{path}'")
        else:
            return [{"type": "error", "data": f"Cannot resolve OS for path: {path}", "stream": "resolver"}]

    def copy(self, source: str, dest: str):
        _validate_path(source)
        _validate_path(dest)
        
        src_os = resolve_os_from_path(source)
        dst_os = resolve_os_from_path(dest)
        
        # INTRA-NODE: Standard copy
        if src_os == dst_os and src_os != "UNKNOWN":
            if src_os == "WINDOWS":
                s = source.replace('/', '\\')
                d = dest.replace('/', '\\')
                return self.executor.execute(f"ps:Copy-Item -Path '{s}' -Destination '{d}' -Recurse -Force")
            else:
                return self.executor.execute(f"bash:cp -r '{source}' '{dest}'")
        
        # INTER-NODE: The True Moat (Memory Bridge)
        
        # WINDOWS -> LINUX (Streaming Implementation)
        if src_os == "WINDOWS" and dst_os == "LINUX":
            try:
                s = source.replace('/', '\\')
                # 1. Truncate/Create destination
                self.executor.execute(f"bash:true > '{dest}'")
                
                # 2. Stream in chunks to avoid host-side OOM and shell limit issues
                with open(s, 'rb') as f:
                    while chunk := f.read(48 * 1024): # ~48KB to stay safe within shell limits after b64
                        b64_payload = base64.b64encode(chunk).decode('utf-8')
                        transfer_cmd = (
                            f"bash:base64 -di << 'EOF_UCSER_CHUNK' >> '{dest}'\n"
                            f"{b64_payload}\n"
                            f"EOF_UCSER_CHUNK"
                        )
                        self.executor.execute(transfer_cmd)
                
                return [{"type": "text", "data": f"Successfully bridged {source} -> {dest} (streamed)", "stream": "bridge"}]
            except Exception as e:
                return [{"type": "error", "data": f"Bridge Copy (W->L) Failed: {str(e)}", "stream": "bridge"}]

        # LINUX -> WINDOWS (Streaming Implementation)
        if src_os == "LINUX" and dst_os == "WINDOWS":
            try:
                d = dest.replace('/', '\\')
                os.makedirs(os.path.dirname(d), exist_ok=True)
                
                # Execute base64 on guest and read stream on host
                it = self.executor.execute(f"bash:base64 '{source}'")
                
                with open(d, 'wb') as f:
                    for item in it:
                        if isinstance(item, dict) and item.get("stream") == "stdout":
                            chunk_b64 = item.get("data", "").strip()
                            if chunk_b64:
                                f.write(base64.b64decode(chunk_b64))
                                
                return [{"type": "text", "data": f"Successfully bridged {source} -> {dest} (streamed)", "stream": "bridge"}]
            except Exception as e:
                return [{"type": "error", "data": f"Bridge Copy (L->W) Failed: {str(e)}", "stream": "bridge"}]

        return [{"type": "error", "data": f"Unsupported cross-boundary operation: {src_os} -> {dst_os}", "stream": "resolver"}]
