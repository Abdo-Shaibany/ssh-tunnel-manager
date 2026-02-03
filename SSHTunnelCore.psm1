<#
.SYNOPSIS
  Core logic for SSH Tunnel Manager: config, plink, encryption, tunnel operations.
  Config stored in %APPDATA%\SSHTunnelManager\tunnels.json with DPAPI-encrypted passwords.
  Logs written to %APPDATA%\SSHTunnelManager\sshx.log
#>

$ErrorActionPreference = 'Stop'
$ConfigDir  = Join-Path $env:APPDATA 'SSHTunnelManager'
$ConfigPath = Join-Path $ConfigDir 'tunnels.json'
$LogPath    = Join-Path $ConfigDir 'sshx.log'

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

function Write-SSHXLog {
    param(
        [string]$Message,
        [string]$Level = 'INFO'
    )
    try {
        if (-not (Test-Path $ConfigDir)) { New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null }
        $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $logLine = "[$timestamp] [$Level] $Message"
        
        # Write to console (visible in terminal)
        $color = switch ($Level) {
            'ERROR' { 'Red' }
            'WARN'  { 'Yellow' }
            'DEBUG' { 'Gray' }
            default { 'Cyan' }
        }
        Write-Host $logLine -ForegroundColor $color
        
        # Also write to log file with shared access
        $fs = [System.IO.FileStream]::new(
            $LogPath, 
            [System.IO.FileMode]::Append, 
            [System.IO.FileAccess]::Write, 
            [System.IO.FileShare]::ReadWrite
        )
        $sw = [System.IO.StreamWriter]::new($fs)
        $sw.WriteLine($logLine)
        $sw.Close()
        $fs.Close()
        
        # Keep log file under 1MB by trimming old entries (check occasionally)
        if ((Get-Random -Maximum 100) -eq 0) {
            $logFile = Get-Item -LiteralPath $LogPath -ErrorAction SilentlyContinue
            if ($logFile -and $logFile.Length -gt 1MB) {
                $lines = Get-Content -LiteralPath $LogPath -Tail 1000
                $lines | Set-Content -LiteralPath $LogPath -Encoding UTF8
            }
        }
    } catch { }
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Get-PlinkPath {
    $p = Get-Command plink -ErrorAction SilentlyContinue
    if ($p) { return $p.Source }
    Write-SSHXLog "plink not found in PATH" -Level 'ERROR'
    throw 'plink not found. PuTTY/Plink must be installed and on PATH.'
}

function Initialize-ConfigDir {
    if (-not (Test-Path $ConfigDir)) { 
        New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null 
        Write-SSHXLog "Created config directory: $ConfigDir"
    }
}


# ---------------------------------------------------------------------------
# Config (load / save)
# ---------------------------------------------------------------------------

function Get-TunnelConfig {
    Initialize-ConfigDir
    if (-not (Test-Path $ConfigPath)) { return @{ Tunnels = @() } }
    $raw = Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction SilentlyContinue
    if (-not $raw) { return @{ Tunnels = @() } }
    try {
        $o = $raw | ConvertFrom-Json
        if (-not $o.PSObject.Properties['Tunnels']) { $o | Add-Member -NotePropertyName Tunnels -NotePropertyValue @() }
        return $o
    } catch {
        Write-SSHXLog "Failed to parse config: $_" -Level 'ERROR'
        return @{ Tunnels = @() }
    }
}

function Save-TunnelConfig { param([object]$Config)
    Initialize-ConfigDir
    $list = [System.Collections.ArrayList]::new()
    foreach ($tn in $Config.Tunnels) {
        [void]$list.Add([pscustomobject]@{
            Name              = [string]$tn.Name
            RemoteHost        = [string]$tn.RemoteHost
            RemotePort        = [int]$tn.RemotePort
            LocalPort         = [int]$tn.LocalPort
            Username          = [string]$tn.Username
            PasswordEncrypted = [string]$tn.PasswordEncrypted
            SshPort           = [int]$tn.SshPort
            Pid               = $tn.Pid
        })
    }
    @{ Tunnels = $list } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $ConfigPath -Encoding UTF8
}

# ---------------------------------------------------------------------------
# Password (DPAPI)
# ---------------------------------------------------------------------------

function Get-EncryptedPassword { param([string]$Plain)
    $sec = ConvertTo-SecureString -String $Plain -AsPlainText -Force
    $sec | ConvertFrom-SecureString
}

function Get-PlainPassword { param([string]$Encrypted)
    $sec = ConvertTo-SecureString -String $Encrypted
    (New-Object PSCredential 'u', $sec).GetNetworkCredential().Password
}

# ---------------------------------------------------------------------------
# Tunnel CRUD and lookup
# ---------------------------------------------------------------------------

function Get-TunnelByName { param([string]$Name)
    $cfg = Get-TunnelConfig
    $cfg.Tunnels | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
}

function Get-AllTunnels {
    # No logging for routine list operations
    return (Get-TunnelConfig).Tunnels
}

function Add-Tunnel {
    param(
        [string]$Name,
        [string]$RemoteHost,
        [int]$RemotePort,
        [int]$LocalPort,
        [string]$Username,
        [string]$PasswordPlain,
        [int]$SshPort = 22
    )
    Write-SSHXLog "Adding tunnel: $Name -> $RemoteHost`:$RemotePort (local: $LocalPort)"
    if ([string]::IsNullOrWhiteSpace($RemoteHost)) { throw 'RemoteHost is required.' }
    if ([string]::IsNullOrWhiteSpace($Username)) { throw 'Username is required.' }
    $cfg = Get-TunnelConfig
    if (Get-TunnelByName -Name $Name) { throw "Tunnel '$Name' already exists." }
    $enc = Get-EncryptedPassword -Plain $PasswordPlain
    $t = [pscustomobject]@{
        Name              = $Name
        RemoteHost        = $RemoteHost
        RemotePort        = [int]$RemotePort
        LocalPort         = [int]$LocalPort
        Username          = $Username
        PasswordEncrypted = $enc
        SshPort           = [int]$SshPort
        Pid               = $null
    }
    $cfg.Tunnels = @($cfg.Tunnels) + $t
    Save-TunnelConfig -Config $cfg
    Write-SSHXLog "Tunnel '$Name' added successfully"
    $t
}

function Update-Tunnel {
    param(
        [string]$Name,
        [string]$NewName,       # rename tunnel
        [string]$RemoteHost,
        [int]$RemotePort,
        [int]$LocalPort,
        [string]$Username,
        [string]$PasswordPlain,
        [int]$SshPort
    )
    $cfg = Get-TunnelConfig
    $idx = -1
    for ($i = 0; $i -lt $cfg.Tunnels.Count; $i++) {
        if ($cfg.Tunnels[$i].Name -eq $Name) { $idx = $i; break }
    }
    if ($idx -lt 0) { throw "Tunnel '$Name' not found." }
    if ($null -ne $NewName -and $NewName -ne '') { $cfg.Tunnels[$idx].Name = $NewName }
    # Only assign when caller explicitly provided a new value; do not overwrite with $null or ""
    if ($null -ne $RemoteHost -and $RemoteHost -ne '') { $cfg.Tunnels[$idx].RemoteHost = $RemoteHost }
    if ($RemotePort -gt 0) { $cfg.Tunnels[$idx].RemotePort = $RemotePort }
    if ($LocalPort -gt 0) { $cfg.Tunnels[$idx].LocalPort = $LocalPort }
    if ($null -ne $Username -and $Username -ne '') { $cfg.Tunnels[$idx].Username = $Username }
    if ($null -ne $PasswordPlain -and $PasswordPlain -ne '') { $cfg.Tunnels[$idx].PasswordEncrypted = Get-EncryptedPassword -Plain $PasswordPlain }
    if ($SshPort -gt 0) { $cfg.Tunnels[$idx].SshPort = $SshPort }
    Save-TunnelConfig -Config $cfg
    $cfg.Tunnels[$idx]
}

function Remove-Tunnel { param([string]$Name)
    $t = Get-TunnelByName -Name $Name
    if (-not $t) { throw "Tunnel '$Name' not found." }
    if ($t.Pid) { Stop-Tunnel -Name $Name }
    $cfg = Get-TunnelConfig
    $cfg.Tunnels = @($cfg.Tunnels | Where-Object { $_.Name -ne $Name })
    Save-TunnelConfig -Config $cfg
}

# ---------------------------------------------------------------------------
# -L format for local port forwarding
# ---------------------------------------------------------------------------

function Get-ForwardArg { param($Tunnel)
    $lp = [int]$Tunnel.LocalPort
    $rp = [int]$Tunnel.RemotePort
    "-L", "${lp}:localhost:${rp}"
}

# ---------------------------------------------------------------------------
# Plink invocation (for runner) — builds args, does not start
# ---------------------------------------------------------------------------

function Get-PlinkInvocationInfo { param([string]$Name)
    $t = Get-TunnelByName -Name $Name
    if (-not $t) { throw "Tunnel '$Name' not found." }
    $plink = Get-PlinkPath
    if ([string]::IsNullOrWhiteSpace($t.RemoteHost)) { throw "Tunnel '$Name' has empty RemoteHost. Edit the tunnel to fix." }
    if ([string]::IsNullOrWhiteSpace($t.Username)) { throw "Tunnel '$Name' has empty Username. Edit the tunnel to fix." }
    $pw = if (-not [string]::IsNullOrWhiteSpace($t.Password)) { $t.Password }
          elseif (-not [string]::IsNullOrWhiteSpace($t.PasswordPlain)) { $t.PasswordPlain }
          elseif (-not [string]::IsNullOrWhiteSpace($t.PasswordEncrypted)) { Get-PlainPassword -Encrypted $t.PasswordEncrypted }
          else { throw "Tunnel '$Name' has no Password, PasswordPlain, or PasswordEncrypted. Edit the JSON to set Password." }
    $fwd = Get-ForwardArg -Tunnel $t
    $plinkArgs = @('-pw', $pw, '-N', '-batch') + $fwd
    $sp = [int]$t.SshPort; if ($sp -gt 0 -and $sp -ne 22) { $plinkArgs += '-P', [string]$sp }
    $plinkArgs += '-l', $t.Username
    $plinkArgs += $t.RemoteHost
    @{ FilePath = $plink; ArgumentList = $plinkArgs }
}

# ---------------------------------------------------------------------------
# Start / Stop / Status (Start runs a runner process that restarts plink on failure)
# ---------------------------------------------------------------------------

function Start-Tunnel { param([string]$Name)
    Write-SSHXLog "Starting tunnel: $Name"
    $t = Get-TunnelByName -Name $Name
    if (-not $t) { 
        Write-SSHXLog "Tunnel '$Name' not found" -Level 'ERROR'
        throw "Tunnel '$Name' not found." 
    }
    if ($t.Pid) {
        $p = Get-Process -Id $t.Pid -ErrorAction SilentlyContinue
        if ($p) { 
            Write-SSHXLog "Tunnel '$Name' already running with PID $($t.Pid)" -Level 'WARN'
            throw "Tunnel '$Name' is already running (PID $($t.Pid))." 
        }
        $t.Pid = $null
    }
    $mod = Get-Module SSHTunnelCore
    $runnerPath = Join-Path $mod.ModuleBase 'SSHTunnelRunner.ps1'
    Write-SSHXLog "Runner path: $runnerPath"
    if (-not (Test-Path -LiteralPath $runnerPath)) { 
        Write-SSHXLog "Runner script not found at: $runnerPath" -Level 'ERROR'
        throw "SSHTunnelRunner.ps1 not found next to SSHTunnelCore.psm1." 
    }
    # Quote path so Start-Process passes it as one arg when it contains spaces (e.g. "E:\internal tools\...")
    $runnerArg = "`"$runnerPath`""
    $proc = Start-Process -FilePath (Get-Command powershell -ErrorAction Stop).Source `
        -ArgumentList @('-NoProfile','-WindowStyle','Hidden','-ExecutionPolicy','Bypass','-File',$runnerArg,'-Name',$Name) `
        -PassThru
    Write-SSHXLog "Started runner process with PID $($proc.Id)"
    $cfg = Get-TunnelConfig
    $updated = $false
    foreach ($x in $cfg.Tunnels) {
        if ($x.Name -eq $Name) { $x.Pid = $proc.Id; $updated = $true; break }
    }
    if (-not $updated) { throw "Tunnel '$Name' disappeared from config." }
    Save-TunnelConfig -Config $cfg
    Write-SSHXLog "Tunnel '$Name' started successfully (PID: $($proc.Id))"
    $proc.Id
}

function Stop-Tunnel { param([string]$Name)
    Write-SSHXLog "Stopping tunnel: $Name"
    $t = Get-TunnelByName -Name $Name
    if (-not $t) { 
        Write-SSHXLog "Tunnel '$Name' not found" -Level 'ERROR'
        throw "Tunnel '$Name' not found." 
    }
    $runnerPid = $t.Pid
    $configDir = Join-Path $env:APPDATA 'SSHTunnelManager'
    $safe = $Name -replace '[^\w\-]', '_'
    $stopFlag = Join-Path $configDir "stop_${safe}.flag"
    $pidFile  = Join-Path $env:TEMP "sshx_${safe}_plink.pid"
    if (-not $runnerPid) { 
        Write-SSHXLog "Tunnel '$Name' has no PID, nothing to stop"
        return $false 
    }
    Write-SSHXLog "Setting stop flag and killing processes (runner PID: $runnerPid)"
    [void](New-Item -ItemType Directory -Path $configDir -Force -ErrorAction SilentlyContinue)
    Set-Content -LiteralPath $stopFlag -Value '1' -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $pidFile) {
        $plinkPid = $null
        if ([int]::TryParse((Get-Content -LiteralPath $pidFile -Raw -ErrorAction SilentlyContinue).Trim(), [ref]$plinkPid)) {
            Write-SSHXLog "Stopping plink process (PID: $plinkPid)"
            Get-Process -Id $plinkPid -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
    }
    Get-Process -Id $runnerPid -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $stopFlag -Force -ErrorAction SilentlyContinue
    $cfg = Get-TunnelConfig
    foreach ($x in $cfg.Tunnels) { if ($x.Name -eq $Name) { $x.Pid = $null; break } }
    Save-TunnelConfig -Config $cfg
    $true
}

function Get-TunnelStatus { param([string]$Name)
    $t = Get-TunnelByName -Name $Name
    if (-not $t) { return $null }
    $running = $false
    if ($t.Pid) {
        $p = Get-Process -Id $t.Pid -ErrorAction SilentlyContinue
        $running = $null -ne $p
        if (-not $running) {
            $cfg = Get-TunnelConfig
            foreach ($x in $cfg.Tunnels) { if ($x.Name -eq $Name) { $x.Pid = $null; break } }
            Save-TunnelConfig -Config $cfg
            $t.Pid = $null
        }
    }
    [pscustomobject]@{ Tunnel = $t; Running = $running; Pid = $t.Pid }
}

function Get-AllTunnelStatuses {
    $tunnels = Get-AllTunnels
    if ($null -eq $tunnels -or $tunnels.Count -eq 0) { return @() }
    $results = @()
    foreach ($t in $tunnels) {
        if ($null -eq $t -or [string]::IsNullOrWhiteSpace($t.Name)) { continue }
        $s = Get-TunnelStatus -Name $t.Name
        if ($s) { $results += $s }
    }
    return $results
}

# ---------------------------------------------------------------------------
# Host key hint (when plink fails with host key)
# ---------------------------------------------------------------------------

function Test-HostKeyError { param([string]$Message)
    return $Message -match 'host key' -or $Message -match 'Host key verification'
}

# ---------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------

Export-ModuleMember -Function @(
    'Write-SSHXLog',
    'Get-TunnelConfig','Save-TunnelConfig',
    'Get-EncryptedPassword','Get-PlainPassword',
    'Get-TunnelByName','Get-AllTunnels','Add-Tunnel','Update-Tunnel','Remove-Tunnel',
    'Get-ForwardArg','Get-PlinkInvocationInfo','Start-Tunnel','Stop-Tunnel','Get-TunnelStatus','Get-AllTunnelStatuses',
    'Get-PlinkPath','Initialize-ConfigDir','Test-HostKeyError'
)
