$command = $args[0]

$forensic_rules = "-Dclippy::unwrap_used",
                  "-Dclippy::expect_used",
                  "-Dclippy::indexing_slicing",
                  "-Dclippy::cast_possible_truncation",
                  "-Dclippy::cast_precision_loss",
                  "-Dclippy::float_cmp",
                  "-Aclippy::pedantic",
                  "-Aclippy::style"

switch ($command) {
    "check" {
        Write-Host "--- Running Forensic Integrity Scan ---" -ForegroundColor Cyan
        cargo clippy --workspace -- $forensic_rules
    }
    "dump" {
        Write-Host "--- Dumping Results to clippy_audit.txt ---" -ForegroundColor Yellow
        # *>&1 captures both stdout and stderr (warnings/errors)
        cargo clippy --workspace -- $forensic_rules *>&1 > clippy_audit.txt
        Write-Host "Done. Check clippy_audit.txt" -ForegroundColor Green
    }
    "core" {
        cargo build --release -p phalanx-core
    }
    "ffi" {
        cargo build --release -p phalanx-ffi
    }
    Default {
        Write-Host "Usage: ./forensic.ps1 [check | dump | core | ffi]" -ForegroundColor Yellow
    }
}