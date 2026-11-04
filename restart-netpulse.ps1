# Restart iTechkey NetPulse after an upgrade.
# Run PowerShell as Administrator:
#   .\restart-netpulse.ps1
# To restart an external database service too:
#   .\restart-netpulse.ps1 -DatabaseServiceName "MySQL80"

[CmdletBinding()]
param(
    [string]$DatabaseServiceName = ""
)

$ErrorActionPreference = "Stop"
$TaskName = "iTechkey NetPulse Monitor"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Python = Join-Path $ScriptDir "venv\Scripts\python.exe"
$Monitor = Join-Path $ScriptDir "itechkey_monitor.py"

function Write-Info([string]$Message) {
    Write-Host "[i] $Message" -ForegroundColor Cyan
}

function Write-Ok([string]$Message) {
    Write-Host "[OK] $Message" -ForegroundColor Green
}

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    throw "Run PowerShell as Administrator, then run .\restart-netpulse.ps1"
}
if (-not (Test-Path -LiteralPath $Python)) {
    throw "NetPulse virtual-environment Python was not found: $Python"
}
if (-not (Test-Path -LiteralPath $Monitor)) {
    throw "NetPulse monitor was not found: $Monitor"
}

Set-Location -LiteralPath $ScriptDir

$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
if ($task.State -eq "Running") {
    Write-Info "Stopping NetPulse background task..."
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    $deadline = (Get-Date).AddSeconds(30)
    do {
        Start-Sleep -Milliseconds 500
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    } while ($task.State -eq "Running" -and (Get-Date) -lt $deadline)
    if ($task.State -eq "Running") {
        throw "NetPulse task did not stop within 30 seconds"
    }
}

if ($DatabaseServiceName) {
    $databaseService = Get-Service -Name $DatabaseServiceName -ErrorAction Stop
    Write-Info "Restarting database service '$($databaseService.Name)'..."
    Restart-Service -Name $databaseService.Name -Force -ErrorAction Stop
    $databaseService.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running,
        [TimeSpan]::FromSeconds(60))
    Write-Ok "Database service is running"
}

Write-Info "Applying NetPulse database schema updates..."
& $Python -c "import itechkey_monitor as monitor; monitor.init_db(); print('Database schema ready')"
if ($LASTEXITCODE -ne 0) {
    throw "Database schema update failed; NetPulse was not restarted"
}
Write-Ok "Database schema is ready"

Write-Info "Starting NetPulse background task..."
Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
Start-Sleep -Seconds 2
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
if ($task.State -ne "Running") {
    throw "NetPulse task did not start. Check Task Scheduler and itechkey_console.log"
}
Write-Ok "NetPulse has restarted successfully"
