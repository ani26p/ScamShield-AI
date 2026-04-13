# ScamShield Extension Icon Resizer
# This script resizes the generated master logo into icon16, icon48, and icon128.

Add-Type -AssemblyName System.Drawing

# Paths
$SourcePath = "C:\Users\anike\.gemini\antigravity\brain\666780ae-c633-48f6-97c2-16972264807b\scamshield_shield_logo_master_1774977042996.png"
$DestDir = "d:\COLLAGE\4th SEM\(2) CSET210 - (DTI) Design thinking & Innovation\New Datasets\Old Files 2\extension\icons"

if (-not (Test-Path $SourcePath)) {
    Write-Error "Source master icon not found at $SourcePath"
    exit
}

$img = [System.Drawing.Image]::FromFile($SourcePath)
$sizes = @(16, 48, 128)

foreach ($size in $sizes) {
    Write-Host "Generating icon$($size).png..."
    $newImg = New-Object System.Drawing.Bitmap($size, $size)
    $g = [System.Drawing.Graphics]::FromImage($newImg)
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.DrawImage($img, 0, 0, $size, $size)
    $g.Dispose()
    
    $dest = Join-Path $DestDir "icon$($size).png"
    $newImg.Save($dest, [System.Drawing.Imaging.ImageFormat]::Png)
    $newImg.Dispose()
}

$img.Dispose()
Write-Host "Done! Icons generated in $DestDir"
