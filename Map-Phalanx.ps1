# --- FUNCTIONS ---
function Get-FileTree {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Path,
        [Parameter()]
        [string]$Indent = ""
    )
    process {
        $treeOutput = @()
        try {
            $resolvedPath = Resolve-Path -Path $Path -ErrorAction Stop
            $items = Get-ChildItem -Path $resolvedPath -ErrorAction Stop
            $itemCount = $items.Count
            for ($i = 0; $i -lt $itemCount; $i++) {
                $item = $items[$i]
                $isLast = $i -eq ($itemCount - 1)
                $junction = if ($isLast) { "\-- " } else { "|-- " }
                $extension = if ($isLast) { "    " } else { "|   " }
                $treeOutput += "$Indent$junction$($item.Name)"
                if ($item.PSIsContainer) {
                    $treeOutput += Get-FileTree -Path $item.FullName -Indent "$Indent$extension"
                }
            }
        } catch { }
        return $treeOutput
    }
}

# --- CONFIGURATION ---
$srcPath = "phalanx-core\src"
$outputFile = "C:\Users\joevo\GoogleDrive\PROJECT_CONTEXT.md"
$noiseTraits = "Debug|Clone|PartialEq|PartialOrd|Serialize|Deserialize|Default|Copy"

$results = @("# Project API, Documentation & Roadmap Summary`nGenerated: $(Get-Date)`n")
$testResults = @("`n---`n## PROJECT UNIT TESTS`n")

# --- 1. INGEST CARGO.TOML ---
$cargoPath = "Cargo.toml"
if (Test-Path $cargoPath) {
    $results += "## Project Configuration (Cargo.toml)"
    $results += "``````toml"
    $results += Get-Content $cargoPath
    $results += "``````"
    $results += "---`n"
}

# --- 2. GENERATE FILE TREE ---
$results += "## Project Structure"
$results += "``````text"
$results += Get-FileTree -Path $srcPath
$results += "``````"
$results += "---`n"

# --- 3. INGEST RUST SOURCE FILES ---
$files = Get-ChildItem -Path $srcPath -Filter "*.rs" -Recurse | Where-Object { $_.FullName -notmatch "target" }

foreach ($file in $files) {
    $relativePath = Resolve-Path -Path $file.FullName -Relative
    $content = Get-Content $file.FullName
    $fileOutput = @()
    $fileTestOutput = @()
    
    $currentSignature = ""
    $currentDocs = @()
    $isCollectingSig = $false
    $currentImplType = "" 
    $braceDepth = 0
    $isTestItem = $false # Specific flag for the current function

    $implRegex = "^(?:pub(?:\(.*\))?\s+)?impl\s*(?:<.*?>)?\s+(?:(?<trait>[\w\d:]+)(?:<.*?>)?\s+for\s+)?(?<type>[\w\d:]+)"

    foreach ($line in $content) {
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }

        # Detect Test Attributes
        if ($trimmed -match "#\[(?:tokio::)?test\]") {
            $isTestItem = $true
        }

        # Context Tracking: impl blocks
        if ($trimmed -match $implRegex) {
            $matches = $Matches
            $typeName = $matches.type
            $traitName = $matches.trait
            if ($typeName -match "::") { $typeName = $typeName.Split(":")[-1] }
            if ($traitName -match "::") { $traitName = $traitName.Split(":")[-1] }
            $currentImplType = if ($traitName) { "$typeName (as $traitName)" } else { $typeName }
        }

        # Brace Tracking
        if ($trimmed.Contains("{")) { $braceDepth++ }
        if ($trimmed.Contains("}")) { 
            $braceDepth-- 
            if ($braceDepth -le 0) { $currentImplType = ""; $braceDepth = 0 }
        }

        # Collect Docs
        if ($trimmed.StartsWith("///")) {
            $currentDocs += $trimmed
            continue
        }

        # Signature Detection
        if ($trimmed -match "^(?:pub(?:\(.*\))?\s+)?(?:async\s+)?(struct|enum|trait|impl|fn)\s+") {
            $isCollectingSig = $true
            $currentSignature = $trimmed
        } elseif ($isCollectingSig) {
            $currentSignature += " $trimmed"
        }

        # Finalize and Render
        if ($isCollectingSig -and ($trimmed.EndsWith("{") -or $trimmed.EndsWith(";"))) {
            $cleanSig = $currentSignature -replace "\s+", " " -replace "\s*\{\s*$", ""
            
            if ($cleanSig -notmatch "(?:derive|impl)\s+\($noiseTraits\)" -and $cleanSig -notmatch "^impl\s") {
                $block = @("#### $cleanSig")
                
                if ($isTestItem) {
                    $block += "**[UNIT TEST]**"
                } elseif ($currentImplType) {
                    $block += "**Context:** Member function of $currentImplType"
                }

                if ($currentDocs.Count -gt 0) { 
                    $block += "``````rust"
                    $block += $currentDocs 
                    $block += "``````"
                }
                $block += ""

                if ($isTestItem) { $fileTestOutput += $block }
                else { $fileOutput += $block }
            }
            # Reset item state
            $currentSignature = ""; $currentDocs = @(); $isCollectingSig = $false; $isTestItem = $false
        }
    }
    if ($fileOutput.Count -gt 0) { $results += "### Source: $relativePath"; $results += $fileOutput; $results += "---" }
    if ($fileTestOutput.Count -gt 0) { $testResults += "### Tests in: $relativePath"; $testResults += $fileTestOutput; $testResults += "---" }
}

# --- 4. SAVE ---
$results + $testResults | Out-File -FilePath $outputFile -Encoding utf8 -Force
Write-Host "`n Phalanx Context updated. Tests isolated and descriptors active." -ForegroundColor Cyan