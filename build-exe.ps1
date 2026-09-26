# ============================================================================
#  build-exe.ps1 — Build iTechkey-Setup.exe
# ============================================================================

$ErrorActionPreference = "Stop"

$Csc = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
$Out = "iTechkey-Setup.exe"
$Src = @("launcher.cs")
if (Test-Path "assembly-info.cs") { $Src += "assembly-info.cs" }

Write-Host "Building $Out..." -ForegroundColor Cyan

$args = @(
    "/target:exe",
    "/out:$Out",
    "/platform:anycpu",
    "/optimize+",
    "/nologo"
)
if (Test-Path "itechkey.ico") {
    $args += "/win32icon:itechkey.ico"
    Write-Host "  Using icon: itechkey.ico" -ForegroundColor Green
}
$args += $Src

& $Csc $args

if ($LASTEXITCODE -eq 0) {
    $size = [math]::Round((Get-Item $Out).Length / 1KB, 2)
    Write-Host ""
    Write-Host "  [OK] Built: $Out ($size KB)" -ForegroundColor Green
    Write-Host ""
} else {
    Write-Host "  [ERR] Build failed" -ForegroundColor Red
    exit 1
}