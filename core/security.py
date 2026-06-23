import json
import base64
import subprocess

class PowerShellAuditor:
    """
    AST-based security auditor for PowerShell commands.
    Uses a temporary pwsh process to parse the AST and check for malicious patterns.
    """
    
    # List of high-risk cmdlets that require auditing or blocking
    RISKY_CMDLETS = [
        "Invoke-WebRequest", "iwr", "curl", "wget",
        "Invoke-RestMethod", "irm",
        "New-Object", # Often used for COM/Net objects
        "Start-Process", "saps",
        "Add-Type", # Compiler access
        "Set-ExecutionPolicy"
    ]

    def audit_command(self, command: str):
        """
        Decomposes the command into AST and scans for threats.
        Returns (is_safe, reason)
        """
        b64_cmd = base64.b64encode(command.encode('utf-8')).decode('utf-8')
        
        # PowerShell script to parse AST and check for risks
        audit_script = f"""
        $ErrorActionPreference = 'Stop'
        $cmd = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("{b64_cmd}"))
        
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($cmd, [ref]$null, [ref]$null)
        
        $findings = @()
        
        # 1. Check for Command Invocation (Cmdlets/Functions)
        $commands = $ast.FindAll({{ $args[0] -is [System.Management.Automation.Language.CommandAst] }}, $true)
        foreach ($c in $commands) {{
            $name = $c.GetCommandName()
            if ($null -ne $name) {{
                if ("{','.join(self.RISKY_CMDLETS)}" -split ',' -contains $name) {{
                    $findings += "Risky cmdlet detected: $name"
                }}
            }}
        }}

        # 2. Check for Obfuscation (e.g. large base64-like strings or encoded expressions)
        $strings = $ast.FindAll({{ $args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst] }}, $true)
        foreach ($s in $strings) {{
            if ($s.Value.Length -gt 100 -and $s.Value -match '^[a-zA-Z0-9+/=]+$') {{
                $findings += "Suspicious large base64-like string detected"
            }}
        }}

        # 3. Check for dynamic code execution (Invoke-Expression / IEX)
        if ($cmd -match '\\biex\\b|Invoke-Expression') {{
             $findings += "Dynamic execution (IEX/Invoke-Expression) detected"
        }}

        if ($findings.Count -gt 0) {{
            return @{{ safe = $false; reasons = $findings }} | ConvertTo-Json -Compress
        }}
        return @{{ safe = $true }} | ConvertTo-Json -Compress
        """

        try:
            # We use a one-off process for the audit to keep the main session clean
            proc = subprocess.Popen(
                ["pwsh", "-NoProfile", "-NonInteractive", "-Command", "-"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = proc.communicate(input=audit_script)
            
            if not stdout.strip():
                return False, f"Audit failed: {stderr}"
                
            result = json.loads(stdout.strip())
            if result.get("safe"):
                return True, ""
            return False, "; ".join(result.get("reasons", ["Unknown risk"]))
            
        except Exception as e:
            return False, f"Auditor exception: {str(e)}"
