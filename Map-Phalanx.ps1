# Configuration
$srcPath = "src"
$outputFile = "GEMINI_CONTEXT.md"
$noiseTraits = "Debug|Clone|PartialEq|PartialOrd|Serialize|Deserialize|Default|Copy"

$results = @("# Project API & Documentation Summary`nGenerated: $(Get-Date)`n")
$files = Get-ChildItem -Path $srcPath -Filter "*.rs" -Recurse | Where-Object { $_.FullName -notmatch "target" }

foreach ($file in $files) {
    $relativePath = Resolve-Path -Path $file.FullName -Relative
    $content = Get-Content $file.FullName
    $fileSignatures = @()
    
    $currentSignature = ""
    $currentDocs = @()
    $isCollectingSig = $false

    foreach ($line in $content) {
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }

        # 1. Collect Doc Comments
        if ($trimmed.StartsWith("///")) {
            $currentDocs += $trimmed
            continue
        }

        # 2. Detect the start of a signature
        if ($trimmed -match "^(?:pub(?:\(.*\))?\s+)?(?:async\s+)?(struct|enum|trait|impl|fn)\s+") {
            $isCollectingSig = $true
            $currentSignature = $trimmed
        } 
        elseif ($isCollectingSig) {
            $currentSignature += " " + $trimmed
        }

        # 3. Handle completion of a signature
        if ($isCollectingSig -and ($trimmed -match "\{" -or $trimmed -match ";")) {
            $finalSig = $currentSignature -replace '\{.*$', ''
            
            # Check for noise traits
            $isNoise = $finalSig -match "impl\s+(?:$noiseTraits)\s+for"

            if ($currentDocs.Count -eq 0 -and $finalSig -match "fn\s+") {
                $fileSignatures += "    // MISSING DOCUMENTATION"
            }
            
            if (-not $isNoise) {
                # Add docs first, then the signature
                if ($currentDocs.Count -gt 0) {
                    $fileSignatures += $currentDocs
                }
                $fileSignatures += $finalSig.Trim() + ";"
                $fileSignatures += "" # Add a newline for readability
            }

            
            # Reset state for next item
            $currentSignature = ""
            $currentDocs = @()
            $isCollectingSig = $false
        } else {
            # If we hit a non-doc, non-sig line while not collecting, clear doc buffer
            if (-not $isCollectingSig -and -not $trimmed.StartsWith("///")) {
                $currentDocs = @()
            }
        }
    }

    if ($fileSignatures.Count -gt 0) {
        $results += "### File: $relativePath"
        $results += "````rust"
        $results += $fileSignatures
        $results += "````"
        $results += "---"
    }
}

# Add this to the very end of your .ps1 script
$charCount = (Get-Item $outputFile).Length
$estimatedTokens = [Math]::Ceiling($charCount / 4)
Write-Host "------------------------------------"
Write-Host "Estimated Token Count: $estimatedTokens" -ForegroundColor Yellow
Write-Host "Status: $(if($estimatedTokens -gt 30000){"Approaching UI limits"}else{"Safe to upload"})"

$results | Out-File -FilePath $outputFile -Encoding utf8
Write-Host "Doc-aware context generated: $outputFile" -ForegroundColor Green