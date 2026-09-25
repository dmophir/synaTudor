<#  syna Windows OpenSSH setup  --  run in an ADMINISTRATOR PowerShell:
        powershell -ExecutionPolicy Bypass -File .\win_setup.ps1 -PubKeyPath .\id_ed25519.pub
    Installs OpenSSH Server (standalone MSI first, to bypass the WSUS/Features-on-Demand
    error 0x80240069; falls back to the in-box feature pointed straight at Windows
    Update), authorizes the SSH public key you pass via -PubKeyPath, lands SSH sessions in
    PowerShell, and opens the firewall. At the end it prints USERNAME + IP -- send those
    two to whoever will SSH in. #>

param(
    [Parameter(Mandatory = $true, HelpMessage = 'Path to the SSH public key file to authorize')]
    [string]$PubKeyPath
)

$ErrorActionPreference = 'Continue'

# Read + validate the public key up front (fail fast before touching the system).
if (-not (Test-Path -LiteralPath $PubKeyPath)) { Write-Error "Public key not found: $PubKeyPath"; exit 1 }
$key = (Get-Content -LiteralPath $PubKeyPath -Raw).Trim()
if ([string]::IsNullOrWhiteSpace($key)) { Write-Error "Public key file is empty: $PubKeyPath"; exit 1 }
if ($key -notmatch '^(ssh-(ed25519|rsa|dss)|ecdsa-sha2-\S+|sk-ssh-\S+|sk-ecdsa-\S+)\s') {
    Write-Error "File does not look like an SSH public key: $PubKeyPath"; exit 1
}

Write-Host '=== syna win setup: installing OpenSSH Server ==='

function Have-Sshd { [bool](Get-Service sshd -ErrorAction SilentlyContinue) }

if (-not (Have-Sshd)) {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $rel   = Invoke-RestMethod 'https://api.github.com/repos/PowerShell/Win32-OpenSSH/releases/latest'
        $asset = $rel.assets | Where-Object { $_.name -like 'OpenSSH-Win64-*.msi' } | Select-Object -First 1
        $out   = Join-Path $env:TEMP $asset.name
        Write-Host "Downloading $($asset.name) ..."
        Invoke-WebRequest $asset.browser_download_url -OutFile $out
        Write-Host 'Installing MSI (silent) ...'
        Start-Process msiexec.exe -ArgumentList "/i `"$out`" /qn /norestart" -Wait
    } catch { Write-Host "MSI path failed: $_" }
}

if (-not (Have-Sshd)) {
    try {
        Write-Host 'MSI unavailable; trying in-box feature via Windows Update (bypass WSUS) ...'
        New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing' -Force | Out-Null
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing' -Name RepairContentServerSource -Type DWord -Value 2
        Restart-Service wuauserv -ErrorAction SilentlyContinue
        Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null
    } catch { Write-Host "FoD path failed: $_" }
}

Start-Service sshd -ErrorAction SilentlyContinue
Set-Service -Name sshd -StartupType 'Automatic' -ErrorAction SilentlyContinue
if (-not (Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
}

New-Item -ItemType Directory -Force -Path "$env:ProgramData\ssh" | Out-Null
$akf = "$env:ProgramData\ssh\administrators_authorized_keys"
if (-not (Test-Path $akf) -or -not (Select-String -Path $akf -SimpleMatch $key -Quiet)) {
    Add-Content -Force -Path $akf -Value $key
}
icacls.exe "$akf" /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F' | Out-Null
if (-not (Test-Path 'HKLM:\SOFTWARE\OpenSSH')) { New-Item -Path 'HKLM:\SOFTWARE\OpenSSH' -Force | Out-Null }
New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -PropertyType String -Force | Out-Null
Restart-Service sshd -ErrorAction SilentlyContinue

$ip = ((Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -like '192.168.*' }).IPAddress) -join ','
$st = (Get-Service sshd -ErrorAction SilentlyContinue).Status

Write-Host ''
Write-Host "USERNAME = $env:USERNAME"
Write-Host "IP       = $ip"
Write-Host "sshd     = $st"
Write-Host '=== done: tell Dylan the USERNAME and IP above ==='
