# ============================================================================
#  iTechkey NetPulse — Windows Installer & Launcher
#  Version : 1.0.0
#  Author  : iTechkey
#  Contact : admin@itechkey.com
# ============================================================================
#
#  Usage: run iTechkey-Setup.exe as Administrator.
#
#    # Allow script execution for this session only
#    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
#
#    # Then run:
#    .\install-windows.ps1
#
#  Or right-click PowerShell and choose "Run as Administrator".
# ============================================================================

$ErrorActionPreference = "Stop"

# ---- Config ----
$VenvDir    = "venv"
$HttpPort   = 80
$HttpsPort  = 443
$TaskName   = "iTechkey NetPulse Monitor"

# ---- Colors ----
function Write-OK   ($m) { Write-Host "  [OK]   $m" -ForegroundColor Green }
function Write-Warn ($m) { Write-Host "  [!]    $m" -ForegroundColor Yellow }
function Write-Err  ($m) { Write-Host "  [ERR]  $m" -ForegroundColor Red }
function Write-Info ($m) { Write-Host "  [i]    $m" -ForegroundColor Cyan }
function Write-Head ($m) {
    Write-Host ""
    Write-Host ("=" * 68) -ForegroundColor Blue
    Write-Host "  $m" -ForegroundColor Blue
    Write-Host ("=" * 68) -ForegroundColor Blue
    Write-Host ""
}

# ---- Banner ----
Clear-Host
Write-Host ""
Write-Host ("  " + ("=" * 64)) -ForegroundColor Blue
Write-Host "  iTechkey NetPulse - Windows Installer" -ForegroundColor Blue
Write-Host "  Version 1.0.0" -ForegroundColor Blue
Write-Host ("  " + ("=" * 64)) -ForegroundColor Blue
Write-Host ""

# ---- Step 0: Working directory ----
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -Path $ScriptDir
Write-Info "Working directory: $ScriptDir"

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Err "Administrator privileges are required to bind port 80 and install the background startup task."
    Write-Info "Run iTechkey-Setup.exe and approve the UAC prompt, or open PowerShell as Administrator."
    exit 1
}

# Verify required files exist
$RequiredFiles = @(
    "itechkey_monitor.py",
    "itechkey_background.py",
    "itechkey_collector.py",
    "itechkey_snmp.py",
    "itechkey_setup.py",
    "requirements.txt"
)

Write-Head "Checking required files"
$missing = @()
foreach ($f in $RequiredFiles) {
    if (Test-Path $f) {
        Write-OK "Found: $f"
    } else {
        Write-Err "Missing: $f"
        $missing += $f
    }
}
if ($missing.Count -gt 0) {
    Write-Host ""
    Write-Err "Required files missing. Please extract the ZIP properly."
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

# Check logo
if (-not (Test-Path "static\itechkey-logo.png")) {
    Write-Warn "Logo missing: static\itechkey-logo.png"
    Write-Warn "App will run without logo. Add it later and restart."
} else {
    Write-OK "Found: static\itechkey-logo.png"
}

# ---- Step 1: Python check ----
Write-Head "Checking Python installation"

$pythonCmd = $null
foreach ($cmd in @("python", "python3", "py")) {
    try {
        $ver = & $cmd --version 2>&1
        if ($LASTEXITCODE -eq 0) {
            $pythonCmd = $cmd
            Write-OK "$cmd detected: $ver"
            break
        }
    } catch {
        continue
    }
}

if (-not $pythonCmd) {
    Write-Err "Python not found!"
    Write-Host ""
    Write-Host "  Please install Python 3.9 or higher from:"
    Write-Host "     https://www.python.org/downloads/" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  IMPORTANT: During installation, check:"
    Write-Host "     [x] Add Python to PATH" -ForegroundColor Yellow
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

# Parse version
$verStr = (& $pythonCmd --version 2>&1) -replace "[^0-9.]", ""
$verParts = $verStr.Split(".")
$major = [int]$verParts[0]
$minor = [int]$verParts[1]
if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 9)) {
    Write-Err "Python 3.9+ required, found $verStr"
    Read-Host "Press Enter to exit"
    exit 1
}
Write-OK "Python version OK ($verStr)"

# ---- Step 2: Virtual environment ----
Write-Head "Setting up virtual environment"

if (Test-Path "$VenvDir\Scripts\python.exe") {
    Write-OK "Virtual environment already exists: $VenvDir"
} else {
    Write-Info "Creating virtual environment: $VenvDir"
    & $pythonCmd -m venv $VenvDir
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Failed to create virtual environment"
        Read-Host "Press Enter to exit"
        exit 1
    }
    Write-OK "Virtual environment created"
}

$venvPython = Join-Path $ScriptDir "$VenvDir\Scripts\python.exe"
$venvPip    = Join-Path $ScriptDir "$VenvDir\Scripts\pip.exe"

if (-not (Test-Path $venvPython)) {
    Write-Err "Virtual environment python not found: $venvPython"
    Read-Host "Press Enter to exit"
    exit 1
}

# Activate venv for this session
& "$VenvDir\Scripts\Activate.ps1"
Write-OK "Virtual environment activated"

# ---- Step 3: Install dependencies ----
Write-Head "Installing Python dependencies"

Write-Info "Upgrading pip..."
& $venvPython -m pip install --upgrade pip --quiet 2>&1 | Out-Null

Write-Info "Installing from requirements.txt (this may take a minute)..."
& $venvPip install -r requirements.txt --quiet
if ($LASTEXITCODE -ne 0) {
    Write-Err "pip install failed"
    Read-Host "Press Enter to exit"
    exit 1
}
Write-OK "All dependencies installed"

# ---- Step 4: Setup wizard ----
Write-Head "Running first-time setup wizard"

if (Test-Path ".env") {
    Write-OK "Config already exists (.env)"
    Write-Info "Skipping setup wizard. Delete .env to reconfigure."
} else {
    Write-Info "Launching setup wizard..."
    Write-Host ""
    & $venvPython itechkey_setup.py
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Setup wizard failed"
        Read-Host "Press Enter to exit"
        exit 1
    }
    Write-OK "Setup complete"
}

# ---- Step 5: Firewall rule (optional) ----
Write-Head "Firewall configuration (optional)"

foreach ($port in @($HttpPort, $HttpsPort)) {
    $ruleName = "iTechkey NetPulse (Port $port)"
    $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-OK "Firewall rule already exists for port $port"
    } else {
        try {
            New-NetFirewallRule -DisplayName $ruleName `
                -Direction Inbound -Protocol TCP -LocalPort $port `
                -Action Allow -Profile Any -ErrorAction Stop | Out-Null
            Write-OK "Firewall rule added for port $port"
        } catch {
            Write-Warn "Could not add firewall rule for port $port (non-fatal)"
        }
    }
}

# ---- Step 6: Register background task ----
Write-Head "Installing background startup task"

$backgroundScript = Join-Path $ScriptDir "itechkey_background.py"
$taskArguments = "-u `"$backgroundScript`""
$action = New-ScheduledTaskAction -Execute $venvPython `
    -Argument $taskArguments -WorkingDirectory $ScriptDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$taskPrincipal = New-ScheduledTaskPrincipal `
    -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) `
    -LogonType S4U -RunLevel Highest
$taskSettings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -MultipleInstances IgnoreNew

try {
    $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existingTask -and $existingTask.State -eq "Running") {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        for ($attempt = 0; $attempt -lt 30; $attempt++) {
            $currentTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
            if (-not $currentTask -or $currentTask.State -ne "Running") { break }
            Start-Sleep -Seconds 1
        }
    }
    Register-ScheduledTask -TaskName $TaskName -Action $action `
        -Trigger $trigger -Principal $taskPrincipal -Settings $taskSettings `
        -Description "Runs iTechkey NetPulse in the background at system startup." `
        -Force | Out-Null
    Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    Write-OK "Background task installed and started. It will start automatically after reboot."
} catch {
    Write-Err "Could not install/start the background task: $_"
    Write-Info "Open Task Scheduler as Administrator and register '$TaskName' manually."
    exit 1
}

# ---- Step 7: Installation complete ----
Write-Head "iTechkey NetPulse is running in the background"

# Get LAN IP
$lanIP = "localhost"
try {
    $lanIP = (Get-NetIPAddress -AddressFamily IPv4 |
              Where-Object { $_.IPAddress -notlike "127.*" -and
                             $_.IPAddress -notlike "169.254.*" } |
              Select-Object -First 1).IPAddress
    if (-not $lanIP) { $lanIP = "localhost" }
} catch {
    $lanIP = "localhost"
}

Write-Host ""
Write-Host ("  " + ("=" * 64)) -ForegroundColor Green
Write-Host "  Setup Complete!" -ForegroundColor Green
Write-Host ("  " + ("=" * 64)) -ForegroundColor Green
Write-Host ""
Write-Host "    Local URL      : " -NoNewline
Write-Host "http://localhost" -ForegroundColor Cyan
Write-Host "    Network URL    : " -NoNewline
Write-Host "http://${lanIP}" -ForegroundColor Cyan
Write-Host "    HTTPS URL      : " -NoNewline
Write-Host "https://${lanIP} (requires TLS certificate configuration)" -ForegroundColor Cyan
Write-Host "    Login          : " -NoNewline
Write-Host "admin / admin" -ForegroundColor Yellow
Write-Host ""
Write-Host "    IMPORTANT: Change password immediately in Settings!" -ForegroundColor Yellow
Write-Host ""
Write-Host "    Close this installer or VS Code; monitoring will continue." -ForegroundColor Green
Write-Host "    Task: $TaskName (runs at Windows startup)" -ForegroundColor Gray
Write-Host "    Console log: $ScriptDir\itechkey_console.log" -ForegroundColor Gray
Write-Host "    Monitor log: $ScriptDir\itechkey.log" -ForegroundColor Gray
Write-Host "    Stop: Stop-ScheduledTask -TaskName '$TaskName'" -ForegroundColor Gray
Write-Host "    Start: Start-ScheduledTask -TaskName '$TaskName'" -ForegroundColor Gray
Write-Host ""