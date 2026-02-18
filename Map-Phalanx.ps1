<#
.SYNOPSIS
    Generates a pure 'Map' of the project architecture.
    FIXES:
    - parser error caused by special characters in comments.
    - Uses single-quoted format strings for safety.
#>

# --- CONFIGURATION ---
$RootPath = "crates\phalanx-core\src" # Adjust to your target crate
$CargoPath = "Cargo.toml"
$OutputFile = "C:\Users\joevo\GoogleDrive\PROJECT_CONTEXT.md"

# --- 1. ARCHITECTURE SUMMARY (Cargo.toml) ---
function Get-CargoSummary {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return "" }
    
    $content = Get-Content $Path -Raw
    $summary = @()
    $summary += "## Workspace Architecture"
    
    if ($content -match 'rust-version\s*=\s*"([^"]+)"') {
        $summary += "* **Rust Version:** $($Matches[1])"
    }

    $keyDeps = @("tokio", "libp2p", "tracing", "postcard", "serde", "sqlx")
    $foundDeps = @()
    foreach ($dep in $keyDeps) {
        if ($content -match "$dep\s*=") { $foundDeps += $dep }
    }
    if ($foundDeps.Count -gt 0) {
        $summary += "* **Key Stack:** $($foundDeps -join ", ")"
    }

    return ($summary -join "`n") + "`n---"
}

# --- 2. PUBLIC INTERFACE MAPPER (Source Scraper) ---
function Get-PublicInterface {
    param([string]$Path)
    
    $output = @()
    $output += "## Public API Surface"
    
    $files = Get-ChildItem -Path $Path -Filter "*.rs" -Recurse | 
             Where-Object { $_.FullName -notmatch "target|tests" }

    foreach ($file in $files) {
        $relPath = Resolve-Path -Path $file.FullName -Relative
        $lines = Get-Content $file.FullName
        $fileItems = @()

        # Regex: Capture Indent (1), Type (2), Rest (3)
        $regexStart = '^(\s*)pub\s+(?:async\s+)?(?:unsafe\s+)?(?:const\s+)?(struct|enum|trait|fn|type|mod)\s+(.*)'
        
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            
            if ($line -match $regexStart) {
                $rawIndent = $Matches[1]
                $type = $Matches[2]
                $rest = $Matches[3]
                
                # Logic for Indentation Prefix
                $prefix = if ($rawIndent.Length -ge 4) { "  -" } else { "-" }

                if ($type -eq "fn") {
                    # --- Multi-Line Accumulator ---
                    $fullSig = $line.Trim()
                    
                    while ($true) {
                        if ($fullSig -match '\{') { break }     # Stop at body
                        if ($fullSig -match ';\s*$') { break }  # Stop at end of decl
                        if (($i + 1) -ge $lines.Count) { break }
                        
                        $i++
                        $nextLine = $lines[$i].Trim()
                        $fullSig += " " + $nextLine
                    }
                    
                    # Clean up signature
                    $fullSig = $fullSig -replace '\s+', ' '
                    $fullSig = $fullSig -replace '\s*\{.*$', '' -replace ';\s*$', ''
                    $sigOnly = $fullSig -replace '^.*?fn\s+', ''
                    
                    # SAFE FORMATTING: Single quotes prevent parser errors
                    $fileItems += '{0} **[fn]** `{1}`' -f $prefix, $sigOnly
                } 
                else {
                    # Structs/Enums
                    $name = $rest -split '[{(;=]' | Select-Object -First 1
                    $name = $name.Trim()
                    
                    # SAFE FORMATTING: Single quotes prevent parser errors
                    $fileItems += '{0} **[{1}]** `{2}`' -f $prefix, $type, $name
                }
            }
        }

        if ($fileItems.Count -gt 0) {
            $output += "`n### File: $relPath"
            $output += $fileItems
        }
    }
    return $output -join "`n"
}

# --- EXECUTION ---
Write-Host "Building Context Map..." -ForegroundColor Cyan

$finalContent = @()
$finalContent += Get-CargoSummary -Path $CargoPath
$finalContent += Get-PublicInterface -Path $RootPath

$finalContent | Out-File -FilePath $OutputFile -Encoding utf8 -Force

Write-Host "Done. Saved to $OutputFile" -ForegroundColor Green