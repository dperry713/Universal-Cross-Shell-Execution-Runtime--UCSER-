param(
    [Parameter(ValueFromPipeline=$true)]
    $InputObject,
    [string]$command
)

# === COLLECT AND UNWRAP INPUT ===
$rawInput = @()
if ($null -ne $InputObject) { $rawInput += $InputObject }

# Collect from pipeline/stdin
if ($input) {
    foreach ($item in $input) {
        if ($null -eq $item) { continue }
        # Avoid duplication
        if ($null -ne $InputObject -and $item -eq $InputObject) { continue }
        $rawInput += $item
    }
}

$objects = @()
foreach ($line in $rawInput) {
    if ($null -eq $line) { continue }
    if ($line -is [string]) {
        if ($line.Trim() -eq "") { continue }
        
        # Surgical UEF unwrap
        if ($line.Trim().StartsWith('{')) {
            try {
                $obj = $line | ConvertFrom-Json
                if ($obj.PSObject.Properties['type'] -and $obj.PSObject.Properties['data']) {
                    $objects += $obj.data
                } else {
                    $objects += $line
                }
            } catch {
                $objects += $line
            }
        } else {
            $objects += $line
        }
    } else {
        $objects += $line
    }
}

# === EXECUTE ===
# Phase 3 Remediation: Execute command as a script block
try {
    # We use a child scope to prevent the command from polluting the wrapper scope
    $ExecutionContext.InvokeCommand.InvokeScript($command) | ForEach-Object {
        $result = $_
        # ... scalar normalization logic below handles this ...
    }
} catch {
    $result = "ERROR: $($_.Exception.Message)"
}

# === SCALAR NORMALIZATION ===
if ($null -eq $result) {
    $result = @()
} elseif (-not ($result -is [System.Collections.IEnumerable]) -or 
         $result -is [string] -or 
         $result -is [datetime] -or 
         $result -is [System.ValueType]) {
    $result = @($result)
}

# === NDJSON OUTPUT (UEF Envelopes) ===
foreach ($r in $result) {
    if ($null -eq $r) {
        @{ type = "null"; data = $null } | ConvertTo-Json -Compress
    } else {
        try {
            # Preserve already-enveloped results
            if ($r -is [PSCustomObject] -and $r.PSObject.Properties['type'] -and $r.PSObject.Properties['data']) {
                $r | ConvertTo-Json -Compress
            } else {
                $type = if ($r -is [string]) { "text" } else { "object" }
                @{ type = $type; data = $r } | ConvertTo-Json -Compress -Depth 10
            }
        } catch {
            @{ type = "raw"; data = "$r" } | ConvertTo-Json -Compress
        }
    }
}
