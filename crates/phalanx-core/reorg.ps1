# --- 1. Infrastructure Setup ---
Write-Host "--- Creating Sibling Structure ---" -ForegroundColor Cyan
$newDirs = @("src/base", "src/primitives", "src/storage", "src/transport", "src/security", "src/drivers/sensors", "src/drivers/optics", "src/bin")
foreach ($dir in $newDirs) { 
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force }
}

# --- 2. The Great Migration ---
Write-Host "--- Moving and renaming files ---" -ForegroundColor Cyan

function Safe-Move ($src, $dest) {
    if (Test-Path $src) { Move-Item $src -Destination $dest -Force }
}

Safe-Move "src/core/config.rs" "src/base/"
Safe-Move "src/core/types.rs" "src/base/"
Safe-Move "src/system/governor.rs" "src/base/"
Safe-Move "src/protocol/shards.rs" "src/primitives/"
Safe-Move "src/security/identity.rs" "src/primitives/"
Safe-Move "src/security/time.rs" "src/primitives/"
Safe-Move "src/storage/guardian.rs" "src/storage/vault.rs"
Safe-Move "src/storage/crucible.rs" "src/storage/"
Safe-Move "src/storage/strategies.rs" "src/storage/"
Safe-Move "src/network/network.rs" "src/transport/swarm.rs"
Safe-Move "src/security/e2ee.rs" "src/security/"
Safe-Move "src/security/sentinel.rs" "src/security/"

if (Test-Path "src/hardware") { Get-ChildItem "src/hardware/*.rs" | Move-Item -Destination "src/drivers/sensors/" -Force }
if (Test-Path "src/forensics") { Get-ChildItem "src/forensics/*.rs" | Move-Item -Destination "src/drivers/optics/" -Force }

Safe-Move "src/main.rs" "src/bin/sentinel.rs"
Safe-Move "src/stronghold.rs" "src/bin/stronghold.rs"
Safe-Move "src/sim.rs" "src/bin/sim.rs"

# --- 3. Automated 'use' Statement Refactoring ---
Write-Host "--- Updating 'use crate::' statements ---" -ForegroundColor Cyan
$mappings = @{
    "crate::core::types"      = "crate::base::types"
    "crate::core::config"     = "crate::base::config"
    "crate::system::governor" = "crate::base::governor"
    "crate::protocol::shards" = "crate::primitives::shards"
    "crate::security::identity" = "crate::primitives::identity"
    "crate::security::time"     = "crate::primitives::time"
    "crate::storage::guardian"  = "crate::storage::vault"
    "crate::network::network"   = "crate::transport::swarm"
    "crate::hardware"           = "crate::drivers::sensors"
    "crate::forensics"          = "crate::drivers::optics"
}

Get-ChildItem -Path "src" -Recurse -Filter "*.rs" | ForEach-Object {
    $content = Get-Content $_.FullName -Raw
    if ($null -ne $content) {
        foreach ($oldPath in $mappings.Keys) {
            $newPath = $mappings[$oldPath]
            $content = $content -replace [regex]::Escape($oldPath), $newPath
        }
        Set-Content -Path $_.FullName -Value $content
    }
}

# --- 4. Creating Sibling Heads ---
Write-Host "--- Planting Module Heads ---" -ForegroundColor Cyan
Set-Content -Path "src/base.rs" -Value "pub mod types;`npub mod config;`npub mod governor;"
Set-Content -Path "src/primitives.rs" -Value "pub mod identity;`npub mod time;`npub mod shards;"
Set-Content -Path "src/storage.rs" -Value "pub mod vault;`npub mod crucible;`npub mod strategies;"
Set-Content -Path "src/transport.rs" -Value "pub mod swarm;"
Set-Content -Path "src/security.rs" -Value "pub mod e2ee;`npub mod sentinel;"
Set-Content -Path "src/drivers.rs" -Value "pub mod sensors;`npub mod optics;"

# --- 5. Cruft Removal ---
Write-Host "--- Removing mod.rs and old folders ---" -ForegroundColor Cyan
Get-ChildItem -Path "src" -Recurse -Filter "mod.rs" | Remove-Item -Force
$oldFolders = @("src/core", "src/system", "src/protocol", "src/network", "src/networking", "src/hardware", "src/forensics", "src/engine")
foreach ($folder in $oldFolders) { if (Test-Path $folder) { Remove-Item $folder -Recurse -Force } }

Write-Host "SUCCESS: SIBLING PATTERN REORG COMPLETE." -ForegroundColor Green