import json
import socket
import subprocess
import threading
import time
import os
from typing import Optional
from security.auditor import CommandAuditor, AuditResult
from core.types import Capability

class PersistentPowerShellAuditor(CommandAuditor):
    """
    Connects to a long-lived PowerShell daemon via a local socket to perform AST auditing.
    Eliminates the 300ms+ overhead of spawning a new pwsh process for every command.
    """
    def __init__(self, host='127.0.0.1', port=59999):
        super().__init__()
        self.host = host
        self.port = port
        self.daemon_proc: Optional[subprocess.Popen] = None
        self._ensure_daemon_running()

    def _ensure_daemon_running(self):
        """Starts the PowerShell listener if it's not responsive."""
        if not self._is_daemon_alive():
            self._spawn_daemon()

    def stop_daemon(self):
        """Terminates the PowerShell process."""
        if self.daemon_proc:
            self.daemon_proc.terminate()
            self.daemon_proc = None

    def _is_daemon_alive(self) -> bool:
        try:
            with socket.create_connection((self.host, self.port), timeout=0.1):
                return True
        except:
            return False

    def _spawn_daemon(self):
        """
        Spawns a hidden PowerShell process that listens for code to parse.
        """
        # PowerShell script that opens a TCP listener and parses AST
        ps_daemon_script = f"""
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, {self.port})
        $listener.Start()
        Write-Host "UCSER PS Auditor Daemon started on {self.port}"
        
        try {{
            while ($true) {{
                $client = $listener.AcceptTcpClient()
                $stream = $client.GetStream()
                $reader = [System.IO.StreamReader]::new($stream)
                $writer = [System.IO.StreamWriter]::new($stream)
                $writer.AutoFlush = $true

                $commandToAudit = $reader.ReadLine()
                if ($null -ne $commandToAudit) {{
                    try {{
                        $errors = $null
                        $tokens = $null
                        $ast = [System.Management.Automation.Language.Parser]::ParseInput($commandToAudit, [ref]$tokens, [ref]$errors)
                        
                        $findings = @()
                        if ($errors) {{
                            $findings += "Parse Error: $($errors.Message)"
                        }}

                        # Visit AST for risky cmdlets
                        $risky = "Invoke-WebRequest","iwr","wget","Invoke-RestMethod","irm","Start-Process","saps","Add-Type","Set-ExecutionPolicy"
                        $commands = $ast.FindAll({{ $args[0] -is [System.Management.Automation.Language.CommandAst] }}, $true)
                        foreach ($c in $commands) {{
                            $name = $c.GetCommandName()
                            if ($null -ne $name -and $risky -contains $name) {{
                                $findings += "Risky cmdlet: $name"
                            }}
                        }}

                        $result = @{{ safe = ($findings.Count -eq 0); reasons = $findings }}
                        $writer.WriteLine(($result | ConvertTo-Json -Compress))
                    }} catch {{
                        $writer.WriteLine('{{"safe": false, "reasons": ["Internal Daemon Error"]}}')
                    }}
                }}
                $client.Close()
            }}
        }} finally {{
            $listener.Stop()
        }}
        """
        self.logger.info("Spawning persistent PowerShell Auditor Daemon...")
        self.daemon_proc = subprocess.Popen(
            ["pwsh", "-NoProfile", "-NonInteractive", "-Command", ps_daemon_script],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        )
        # Give it a moment to bind the port
        time.sleep(1.5)

    def parse(self, command: str):
        audit_res = self.audit(command)
        class LegacyAST:
            def __init__(self, findings):
                self.nodes = []
                self.findings = findings
        return LegacyAST(audit_res.reasons if not audit_res.is_safe else [])

    def rewrite(self, command: str, ast: Any) -> str:
        return command

    def audit(self, command: str) -> AuditResult:
        import base64
        self._ensure_daemon_running()
        try:
            with socket.create_connection((self.host, self.port), timeout=2.0) as sock:
                # Base64 encode to preserve structure and newlines
                encoded_cmd = base64.b64encode(command.encode('utf-8')).decode('utf-8')
                sock.sendall((encoded_cmd + "\n").encode('utf-8'))
                response = sock.recv(4096).decode('utf-8')
                data = json.loads(response)
                
                reasons = data.get("reasons", [])
                caps = {Capability.EXEC}
                if not data.get("safe"):
                    # Map common risks to capabilities if needed
                    pass 

                return AuditResult(data.get("safe", False), reasons, caps)
        except Exception as e:
            return AuditResult(False, [f"Auditor Daemon Connection Error: {str(e)}"], set())
