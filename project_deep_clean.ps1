# ScamShield Final Project Deep Clean
# Deletes diagnostic logs, redundant helper scripts, and ML temporary artifacts.

$FilesToDelete = @(
    "diag_out.txt",
    "diagnose.py",
    "predictor.py",
    "utils.py",
    "generate_icons.py",
    "extension/resize_icons.ps1"
)

$FoldersToDelete = @(
    "catboost_info",
    "catboost_temp_07d554ef6c4f44d8af5c9659c61d520a",
    "catboost_temp_35437ec7708640e49e2590e8ef4d0b18"
)

Write-Host "Starting ScamShield Deep Clean..." -ForegroundColor Cyan

foreach ($f in $FilesToDelete) {
    if (Test-Path $f) {
        Remove-Item $f -Force
        Write-Host "Removed file: $f" -ForegroundColor Green
    }
}

foreach ($d in $FoldersToDelete) {
    if (Test-Path $d) {
        Remove-Item $d -Recurse -Force
        Write-Host "Removed directory: $d" -ForegroundColor Green
    }
}

Write-Host "Project is now lean and production-ready!" -ForegroundColor Cyan
