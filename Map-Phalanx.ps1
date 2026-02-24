<#
.SYNOPSIS
    Phalanx Core Architect Context Scraper v12.1
    FIXES:
    - Multi-line Signatures: Implements a lookahead accumulator for long signatures.
    - Reference Handling: Explicitly ignores '&' during signature capture.
    - AST Integrity: Maintains v12 unit-struct and brace-depth logic.
#>

$RootPath = 'crates\phalanx-core\src'
$CargoPath = 'Cargo.toml'
$OutputFile = 'C:\Users\joevo\GoogleDrive\PROJECT_CONTEXT.md'
$NL = [System.Environment]::NewLine

function Get-SystemMetadata {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return '## Workspace Architecture' + $NL + '* Metadata unavailable.' }
    $raw = Get-Content $Path -Raw
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('## Workspace Architecture')
    if ($raw -match 'rust-version\s*=\s*"([^"]+)"') { 
        [void]$sb.AppendLine(('* **Rust Version:** {0}' -f $Matches[1])) 
    }
    $stack = @('tokio', 'libp2p', 'tracing', 'postcard', 'serde', 'sqlx')
    $found = @()
    foreach ($dep in $stack) { if ($raw -match ("{0}\s*=" -f $dep)) { $found += $dep } }
    if ($found.Count) { 
        [void]$sb.AppendLine(('* **Key Stack:** {0}' -f ($found -join ', '))) 
    }
    [void]$sb.AppendLine('---')
    return $sb.ToString()
}

function Get-ProjectInterface {
    param([string]$Path)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('## Public API Surface')
    
    $allFiles = Get-ChildItem -Path $Path -Filter '*.rs' -Recurse | Where-Object { $_.FullName -notmatch 'target|tests' }

    foreach ($file in $allFiles) {
        $rel = Resolve-Path -Path $file.FullName -Relative
        $lines = Get-Content $file.FullName
        $fileHasContent = $false
        $tempSb = New-Object System.Text.StringBuilder
        
        $i = 0
        while ($i -lt $lines.Count) {
            $line = $lines[$i]
            if ([string]::IsNullOrWhiteSpace($line)) { $i++; continue }

            # 1. SKIP TEST BLOCKS
            if ($line -match '^\s*#\[cfg\(test\)\]') {
                $d = 0; $started = $false
                while ($i -lt $lines.Count) {
                    if ($lines[$i] -match '\{') { $started = $true }
                    $d += ($lines[$i].ToCharArray() | Where-Object { $_ -eq '{' }).Count
                    $d -= ($lines[$i].ToCharArray() | Where-Object { $_ -eq '}' }).Count
                    if ($started -and $d -le 0) { break }; $i++
                }
                $i++; continue
            }

            # 2. DATA STRUCTURES (Unit, Tuple, Block)
            if ($line -match '^\s*(?:#\[.*?\]\s*)*(?:pub(?:\s*\(.*?\))?\s+)?(?:struct|enum|type)\b') {
                $fileHasContent = $true
                $fullDef = New-Object System.Collections.Generic.List[string]
                $d = 0; $started = $false
                
                while ($i -lt $lines.Count) {
                    $cur = $lines[$i]; [void]$fullDef.Add($cur)
                    if ($cur -match '\{') { $started = $true }
                    if (-not $started -and $cur -match ';\s*(?://.*)?$') { break }
                    
                    $d += ($cur.ToCharArray() | Where-Object { $_ -eq '{' }).Count
                    $d -= ($cur.ToCharArray() | Where-Object { $_ -eq '}' }).Count
                    if ($started -and $d -le 0) { break }
                    $i++
                }
                [void]$tempSb.AppendLine('')
                [void]$tempSb.AppendLine('**[data]**')
                [void]$tempSb.AppendLine('```rust')
                [void]$tempSb.AppendLine(($fullDef -join $NL))
                [void]$tempSb.AppendLine('```')
            }
            # 3. API SIGNATURES (Impl / Trait)
            elseif ($line -match '^\s*(?:pub\s+)?(?:impl|trait)\b') {
                $fileHasContent = $true
                $header = $line.Trim() -replace '\{.*$', ''
                [void]$tempSb.AppendLine('')
                [void]$tempSb.AppendLine(('**[api]** `{0}`' -f $header))
                
                $d = 0; $started = $false
                while ($i -lt $lines.Count) {
                    $cur = $lines[$i]; $prevD = $d
                    if ($cur -match '\{') { $started = $true }
                    $d += ($cur.ToCharArray() | Where-Object { $_ -eq '{' }).Count
                    $d -= ($cur.ToCharArray() | Where-Object { $_ -eq '}' }).Count
                    
                    # Capture Property if inside impl root
                    if ($started -and $prevD -eq 1) {
                        # Handle Multi-line Function Signatures
                        if ($cur -match '^\s*(?:pub\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+') {
                            $fullSig = $cur.Trim()
                            $lookIdx = $i
                            while ($fullSig -notmatch '\{|;' -and $lookIdx -lt ($lines.Count - 1)) {
                                $lookIdx++
                                $fullSig += ' ' + $lines[$lookIdx].Trim()
                            }
                            $cleanSig = $fullSig -replace '\{.*$', '' -replace ';.*$', ''
                            [void]$tempSb.AppendLine(('- `{0};`' -f $cleanSig.Trim()))
                        }
                        # Handle Types and Consts
                        elseif ($cur -match '^\s*(?:pub\s+)?(?:type|const)\s+') {
                            $fileEntries += ('- `{0}`' -f ($cur.Trim() -replace '\{.*$', ';'))
                            [void]$tempSb.AppendLine(('- `{0}`' -f ($cur.Trim() -replace '\{.*$', ';')))
                        }
                    }
                    if ($started -and $d -le 0) { break }; $i++
                }
            }
            $i++
        }

        if ($fileHasContent) {
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine(('### File: {0}' -f $rel))
            [void]$sb.Append($tempSb.ToString())
        }
    }
    return $sb.ToString()
}

Write-Host 'Phalanx v12.1: The Reference Guard Active...' -ForegroundColor Cyan
$finalContent = (Get-SystemMetadata -Path $CargoPath) + $NL + (Get-ProjectInterface -Path $RootPath)
[System.IO.File]::WriteAllText($OutputFile, $finalContent)
Write-Host 'Success: Context Map Synchronized.' -ForegroundColor Green