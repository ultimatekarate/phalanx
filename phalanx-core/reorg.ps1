# --- 1. Infrastructure Setup ---
Write-Host "🏗️ Creating Sibling Structure..." -ForegroundColor Cyan
$newDirs = @("src/base", "src/primitives", "src/storage", "src/transport", "src/security", "src/drivers/sensors", "src/drivers/optics", "src/bin")
foreach ($dir in $newDirs) { New-Item -ItemType Directory -Path $dir -Force }

# --- 2. The Great Migration ---
Write-Host "🚚 Moving and renaming files..." -ForegroundColor Cyan

# Base & Primitives
if (Test-Path "src/core/config.rs") { Move-Item "src/core/config.rs" -Destination "src/base/" }
if (Test-Path "src/core/types.rs") { Move-Item "src/core/types.rs" -Destination "src/base/" }
if (Test-Path "src/system/governor.rs") { Move-Item "src/system/governor.rs" -Destination "src/base/" }
if (Test-Path "src/protocol/shards.rs") { Move-Item "src/protocol/shards.rs" -Destination "src/primitives/" }
if (Test-Path "src/security/identity.rs") { Move-Item "src/security/identity.rs" -Destination "src/primitives/" }
if (Test-Path "src/security/time.rs") { Move-Item "src/security/time.rs" -Destination "src/primitives/" }

# Storage
if (Test-Path "src/storage/guardian.rs") { Move-Item "src/storage/guardian.rs" -Destination "src/storage/vault.rs" }
if (Test-Path "src/storage/crucible.rs") { Move-Item "src/storage/crucible.rs" -Destination "src/storage/" }
if (Test-Path "src/storage/strategies.rs") { Move-Item "src/storage/strategies.rs" -Destination "src/storage/" }

# Transport & Security
if (Test-Path "src/network/network.rs") { Move-Item "src/network/network.rs" -Destination "src/transport/swarm.rs" }
if (Test-Path "src/security/e2ee.rs") { Move-Item "src/security/e2ee.rs" -Destination "src/security/" }
if (Test-Path "src/security/sentinel.rs") { Move-Item "src/security/sentinel.rs" -Destination "src/security/" }

# Drivers (Hardware & Forensics)
if (Test-Path "src/hardware") { Get-ChildItem "src/hardware/*.rs" | Move-Item -Destination "src/drivers/sensors/" }
if (Test-Path "src/forensics") { Get-ChildItem "src/forensics/*.rs" | Move-Item -Destination "src/drivers/optics/" }

# Binaries
if (Test-Path "src/main.rs") { Move-Item "src/main.rs" -Destination "src/bin/sentinel.rs" }
if (Test-Path "src/stronghold.rs") { Move-Item "src/stronghold.rs" -Destination "src/bin/stronghold.rs" }
if (Test-Path "src/sim.rs") { Move-Item "src/sim.rs" -Destination "src/bin/sim.rs" }

# --- 3. Automated 'use' Statement Refactoring ---
Write-Host "📝 Updating 'use crate::' statements..." -ForegroundColor Cyan
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
    foreach ($oldPath in $mappings.Keys) {
        $newPath = $mappings[$oldPath]
        $content = $content -replace [regex]::Escape($oldPath), $newPath
    }
    Set-Content -Path $_.FullName -Value $content
}

# --- 4. Creating Sibling Heads ---
Write-Host "🌳 Creating Sibling Head files..." -ForegroundColor Cyan
"pub mod types;`npub mod config;`npub mod governor;" | Out-File -FilePath "src/base.rs" -Encoding utf8
"pub mod identity;`npub mod time;`npub mod shards;" | Out-File -FilePath "src/primitives.rs" -Encoding utf8
"pub mod vault;`npub mod crucible;`npub mod strategies;" | Out-File -FilePath "src/storage.rs" -Encoding utf8
"pub mod swarm;" | Out-File -FilePath "src/transport.rs" -Encoding utf8
"pub mod e2ee;`npub mod sentinel;" | Out-File -FilePath "src/security.rs" -Encoding utf8
"pub mod sensors;`npub mod optics;" | Out-File -FilePath "src/drivers.rs" -Encoding utf8
"pub mod sentinel;`npub mod stronghold;`npub mod sim;" | Out-File -FilePath "src/bin.rs" -Encoding utf8

# --- 5. Final Purge ---
Write-Host "🧹 NUKING mod.rs and old directories..." -ForegroundColor Cyan
Get-ChildItem -Path "src" -Recurse -Filter "mod.rs" | Remove-Item -Force
$oldFolders = @("src/core", "src/system", "src/protocol", "src/network", "src/networking", "src/hardware", "src/forensics")
foreach ($folder in $oldFolders) { if (Test-Path $folder) { Remove-Item $folder -Recurse -Force } }

Write-Host "✅ SIBLING PATTERN REORG COMPLETE." -ForegroundColor Green