# --- CONFIGURATION ---
$srcPath = "phalanx-core\src"
$rootPath = "." 
$roadmapRootDir = "roadmaps" # Your local root for the roadmap hierarchy
$outputFile = "C:\Users\joevo\GoogleDrive\PROJECT_CONTEXT.md"
$noiseTraits = "Debug|Clone|PartialEq|PartialOrd|Serialize|Deserialize|Default|Copy"

$results = @("# Project API, Documentation & Roadmap Summary`nGenerated: $(Get-Date)`n")

# --- 1. INGEST CARGO.TOML ---
$cargoPath = Join-Path $rootPath "Cargo.toml"
if (Test-Path $cargoPath) {
    $results += "## Project Configuration (Cargo.toml)"
    $results += "````toml"
    $results += Get-Content $cargoPath
    $results += "````"
    $results += "---`n"
    Write-Host "Manifest Loaded." -ForegroundColor Green
}

# --- 2. INGEST ROADMAP HIERARCHY (Recursive) ---
if (Test-Path $roadmapRootDir) {
    $results += "## PROJECT ROADMAP HIERARCHY"
    $results += "The following sections represent the project's strategic hierarchy. Nested paths indicate domain-specific sub-plans."
    
    $roadmapFiles = Get-ChildItem -Path $roadmapRootDir -Filter "*.md" -Recurse
    foreach ($file in $roadmapFiles) {
        # Create a breadcrumb label (e.g., roadmaps > ui > mobile-ui-roadmap.md)
        $relativePath = $file.FullName.Replace((Get-Item $roadmapRootDir).Parent.FullName, "").TrimStart("\").Replace("\", " > ")
        
        $results += "### ROADMAP LOCATION: $relativePath"
        $results += "````markdown"
        $results += Get-Content $file.FullName
        $results += "````"
        $results += "---"
    }
    Write-Host "Roadmaps Ingested: $($roadmapFiles.Count) files mapped." -ForegroundColor Green
} else {
    Write-Host "Warning: Roadmap directory not found at $roadmapRootDir" -ForegroundColor Yellow
}

# --- 3. INGEST RUST SOURCE FILES ---
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

        if ($trimmed.StartsWith("///")) {
            $currentDocs += $trimmed
            continue
        }

        if ($trimmed -match "^(?:pub(?:\(.*\))?\s+)?(?:async\s+)?(struct|enum|trait|impl|fn)\s+") {
            $isCollectingSig = $true
            $currentSignature = $trimmed
        } 
        elseif ($isCollectingSig) {
            $currentSignature += " $trimmed"
        }

        if ($isCollectingSig -and ($trimmed.EndsWith("{") -or $trimmed.EndsWith(";"))) {
            $cleanSig = $currentSignature -replace "\s+", " " -replace "\s*\{\s*$", ""
            
            if ($cleanSig -notmatch "(?:derive|impl)\s+\($noiseTraits\)") {
                # Documentation Check
                if ($currentDocs.Count -gt 0) {
                    $fileSignatures += $currentDocs
                } else {
                    $fileSignatures += "// WARNING: NO FUNCTIONAL DOCUMENTATION PROVIDED"
                }
                
                $fileSignatures += $cleanSig
                $fileSignatures += ""
            }
            
            $currentSignature = ""
            $currentDocs = @()
            $isCollectingSig = $false
        } else {
            if (-not $isCollectingSig -and -not $trimmed.StartsWith("///")) {
                $currentDocs = @()
            }
        }
    }

    if ($fileSignatures.Count -gt 0) {
        $results += "### Source: $relativePath"
        $results += "````rust"
        $results += $fileSignatures
        $results += "````"
        $results += "---"
    }
}

# --- 4. SAVE AND SYNC ---
$results | Out-File -FilePath $outputFile -Encoding utf8 -Force
(Get-Item $outputFile).LastWriteTime = Get-Date

if (Test-Path $outputFile) {
    $charCount = (Get-Item $outputFile).Length
    $estimatedTokens = [Math]::Ceiling($charCount / 4)
    Write-Host "`n Phalanx Context updated with Roadmap Hierarchy." -ForegroundColor Cyan
    Write-Host "Total Estimated Tokens: $estimatedTokens" -ForegroundColor Yellow
}