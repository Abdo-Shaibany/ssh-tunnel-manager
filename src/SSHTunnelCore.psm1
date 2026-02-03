<#
.SYNOPSIS
  Core logic for SSH Tunnel Manager: config, ssh, encryption, tunnel operations.
  Uses Windows built-in OpenSSH (ssh.exe) - no external dependencies like PuTTY.
  Config stored in %APPDATA%\SSHTunnelManager\tunnels.json with DPAPI-encrypted passwords.
  Supports both password and SSH key authentication.
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

function Get-SshPath {
    # First check for OpenSSH in Windows System32 (built-in)
    $systemSsh = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
    if (Test-Path $systemSsh) { return $systemSsh }
    
    # Then check PATH
    $p = Get-Command ssh -ErrorAction SilentlyContinue
    if ($p) { return $p.Source }
    
    Write-SSHXLog "ssh.exe not found" -Level 'ERROR'
    throw 'ssh.exe not found. Windows OpenSSH must be enabled. Go to Settings > Apps > Optional Features > Add OpenSSH Client.'
}

# Backward compatibility alias
function Get-PlinkPath { Get-SshPath }

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
            # New fields
            IdentityFile      = [string]$tn.IdentityFile      # SSH key path (optional)
            AuthMethod        = [string]$tn.AuthMethod        # 'password' or 'key'
            Group             = [string]$tn.Group             # Tunnel group (optional)
            ConnectTimeout    = if ($tn.ConnectTimeout -gt 0) { [int]$tn.ConnectTimeout } else { 30 }  # Connection timeout in seconds
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

function Test-ValidPort {
    param([int]$Port, [string]$PortName = 'Port')
    if ($Port -lt 1 -or $Port -gt 65535) {
        throw "$PortName must be between 1 and 65535 (got: $Port)."
    }
    return $true
}

function Test-LocalPortAvailable {
    param([int]$LocalPort, [string]$ExcludeTunnelName = $null)
    $cfg = Get-TunnelConfig
    foreach ($t in $cfg.Tunnels) {
        if ($ExcludeTunnelName -and $t.Name -eq $ExcludeTunnelName) { continue }
        if ([int]$t.LocalPort -eq $LocalPort) {
            throw "Local port $LocalPort is already used by tunnel '$($t.Name)'."
        }
    }
    return $true
}

function Test-DuplicateTunnel {
    param(
        [string]$RemoteHost,
        [int]$RemotePort,
        [int]$LocalPort,
        [string]$ExcludeTunnelName = $null
    )
    $cfg = Get-TunnelConfig
    foreach ($t in $cfg.Tunnels) {
        if ($ExcludeTunnelName -and $t.Name -eq $ExcludeTunnelName) { continue }
        # Check if same remote target AND same local port
        if ($t.RemoteHost -eq $RemoteHost -and [int]$t.RemotePort -eq $RemotePort -and [int]$t.LocalPort -eq $LocalPort) {
            throw "A tunnel with the same configuration already exists: '$($t.Name)' (localhost:$LocalPort -> ${RemoteHost}:$RemotePort)."
        }
    }
    return $true
}

function Add-Tunnel {
    param(
        [string]$Name,
        [string]$RemoteHost,
        [int]$RemotePort,
        [int]$LocalPort,
        [string]$Username,
        [string]$PasswordPlain,
        [int]$SshPort = 22,
        [string]$IdentityFile = '',      # SSH key path
        [string]$AuthMethod = 'password', # 'password' or 'key'
        [string]$Group = '',              # Tunnel group
        [int]$ConnectTimeout = 30         # Connection timeout in seconds
    )
    Write-SSHXLog "Adding tunnel: $Name -> $RemoteHost`:$RemotePort (local: $LocalPort, auth: $AuthMethod)"
    
    # Validate required fields
    if ([string]::IsNullOrWhiteSpace($Name)) { throw 'Name is required.' }
    if ([string]::IsNullOrWhiteSpace($RemoteHost)) { throw 'RemoteHost is required.' }
    if ([string]::IsNullOrWhiteSpace($Username)) { throw 'Username is required.' }
    
    # Validate authentication
    if ($AuthMethod -eq 'key') {
        if ([string]::IsNullOrWhiteSpace($IdentityFile)) { throw 'Identity file (SSH key) is required for key authentication.' }
        if (-not (Test-Path -LiteralPath $IdentityFile)) { throw "Identity file not found: $IdentityFile" }
    } else {
        if ([string]::IsNullOrWhiteSpace($PasswordPlain)) { throw 'Password is required for password authentication.' }
    }
    
    # Validate port ranges
    Test-ValidPort -Port $RemotePort -PortName 'Remote Port' | Out-Null
    Test-ValidPort -Port $LocalPort -PortName 'Local Port' | Out-Null
    if ($SshPort -le 0) { $SshPort = 22 }
    Test-ValidPort -Port $SshPort -PortName 'SSH Port' | Out-Null
    
    # Validate timeout
    if ($ConnectTimeout -le 0) { $ConnectTimeout = 30 }
    if ($ConnectTimeout -gt 300) { $ConnectTimeout = 300 }  # Max 5 minutes
    
    # Check for duplicate name
    $cfg = Get-TunnelConfig
    if (Get-TunnelByName -Name $Name) { throw "Tunnel '$Name' already exists." }
    
    # Check local port not already in use
    Test-LocalPortAvailable -LocalPort $LocalPort | Out-Null
    
    # Check for duplicate tunnel config
    Test-DuplicateTunnel -RemoteHost $RemoteHost -RemotePort $RemotePort -LocalPort $LocalPort | Out-Null
    
    $enc = if ($AuthMethod -eq 'password' -and -not [string]::IsNullOrWhiteSpace($PasswordPlain)) {
        Get-EncryptedPassword -Plain $PasswordPlain
    } else { '' }
    
    $t = [pscustomobject]@{
        Name              = $Name
        RemoteHost        = $RemoteHost
        RemotePort        = [int]$RemotePort
        LocalPort         = [int]$LocalPort
        Username          = $Username
        PasswordEncrypted = $enc
        SshPort           = [int]$SshPort
        Pid               = $null
        IdentityFile      = $IdentityFile
        AuthMethod        = $AuthMethod
        Group             = $Group
        ConnectTimeout    = [int]$ConnectTimeout
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
        [int]$SshPort,
        [string]$IdentityFile,      # SSH key path
        [string]$AuthMethod,        # 'password' or 'key'
        [string]$Group,             # Tunnel group
        [int]$ConnectTimeout        # Connection timeout in seconds
    )
    $cfg = Get-TunnelConfig
    $idx = -1
    for ($i = 0; $i -lt $cfg.Tunnels.Count; $i++) {
        if ($cfg.Tunnels[$i].Name -eq $Name) { $idx = $i; break }
    }
    if ($idx -lt 0) { throw "Tunnel '$Name' not found." }
    
    $existing = $cfg.Tunnels[$idx]
    
    # Check for duplicate name if renaming
    if ($null -ne $NewName -and $NewName -ne '' -and $NewName -ne $Name) {
        if (Get-TunnelByName -Name $NewName) { throw "Tunnel '$NewName' already exists." }
    }
    
    # Validate ports if changing them
    if ($RemotePort -gt 0 -and $RemotePort -ne [int]$existing.RemotePort) {
        Test-ValidPort -Port $RemotePort -PortName 'Remote Port' | Out-Null
    }
    if ($LocalPort -gt 0 -and $LocalPort -ne [int]$existing.LocalPort) {
        Test-ValidPort -Port $LocalPort -PortName 'Local Port' | Out-Null
        Test-LocalPortAvailable -LocalPort $LocalPort -ExcludeTunnelName $Name | Out-Null
    }
    if ($SshPort -gt 0 -and $SshPort -ne [int]$existing.SshPort) {
        Test-ValidPort -Port $SshPort -PortName 'SSH Port' | Out-Null
    }
    
    # Validate identity file if provided
    if ($null -ne $IdentityFile -and $IdentityFile -ne '' -and -not (Test-Path -LiteralPath $IdentityFile)) {
        throw "Identity file not found: $IdentityFile"
    }
    
    # Validate timeout
    if ($ConnectTimeout -gt 300) { $ConnectTimeout = 300 }  # Max 5 minutes
    
    # Check for duplicate tunnel config if changing remote host/port/local port
    $finalRemoteHost = if ($null -ne $RemoteHost -and $RemoteHost -ne '') { $RemoteHost } else { $existing.RemoteHost }
    $finalRemotePort = if ($RemotePort -gt 0) { $RemotePort } else { [int]$existing.RemotePort }
    $finalLocalPort = if ($LocalPort -gt 0) { $LocalPort } else { [int]$existing.LocalPort }
    
    # Only check for duplicates if something changed
    $configChanged = ($finalRemoteHost -ne $existing.RemoteHost) -or ($finalRemotePort -ne [int]$existing.RemotePort) -or ($finalLocalPort -ne [int]$existing.LocalPort)
    if ($configChanged) {
        Test-DuplicateTunnel -RemoteHost $finalRemoteHost -RemotePort $finalRemotePort -LocalPort $finalLocalPort -ExcludeTunnelName $Name | Out-Null
    }
    
    # Apply changes
    if ($null -ne $NewName -and $NewName -ne '') { $cfg.Tunnels[$idx].Name = $NewName }
    if ($null -ne $RemoteHost -and $RemoteHost -ne '') { $cfg.Tunnels[$idx].RemoteHost = $RemoteHost }
    if ($RemotePort -gt 0) { $cfg.Tunnels[$idx].RemotePort = $RemotePort }
    if ($LocalPort -gt 0) { $cfg.Tunnels[$idx].LocalPort = $LocalPort }
    if ($null -ne $Username -and $Username -ne '') { $cfg.Tunnels[$idx].Username = $Username }
    if ($null -ne $PasswordPlain -and $PasswordPlain -ne '') { $cfg.Tunnels[$idx].PasswordEncrypted = Get-EncryptedPassword -Plain $PasswordPlain }
    if ($SshPort -gt 0) { $cfg.Tunnels[$idx].SshPort = $SshPort }
    
    # New fields - use PSObject to handle missing properties gracefully
    if ($null -ne $IdentityFile) { 
        if (-not $cfg.Tunnels[$idx].PSObject.Properties['IdentityFile']) {
            $cfg.Tunnels[$idx] | Add-Member -NotePropertyName 'IdentityFile' -NotePropertyValue $IdentityFile
        } else {
            $cfg.Tunnels[$idx].IdentityFile = $IdentityFile 
        }
    }
    if ($null -ne $AuthMethod -and $AuthMethod -ne '') { 
        if (-not $cfg.Tunnels[$idx].PSObject.Properties['AuthMethod']) {
            $cfg.Tunnels[$idx] | Add-Member -NotePropertyName 'AuthMethod' -NotePropertyValue $AuthMethod
        } else {
            $cfg.Tunnels[$idx].AuthMethod = $AuthMethod 
        }
    }
    if ($null -ne $Group) {  # Allow empty string to clear group
        if (-not $cfg.Tunnels[$idx].PSObject.Properties['Group']) {
            $cfg.Tunnels[$idx] | Add-Member -NotePropertyName 'Group' -NotePropertyValue $Group
        } else {
            $cfg.Tunnels[$idx].Group = $Group 
        }
    }
    if ($ConnectTimeout -gt 0) { 
        if (-not $cfg.Tunnels[$idx].PSObject.Properties['ConnectTimeout']) {
            $cfg.Tunnels[$idx] | Add-Member -NotePropertyName 'ConnectTimeout' -NotePropertyValue $ConnectTimeout
        } else {
            $cfg.Tunnels[$idx].ConnectTimeout = $ConnectTimeout 
        }
    }
    
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
    # Explicitly bind to 127.0.0.1 to ensure IPv4 and consistent behavior
    # Format: -L bind_address:port:host:hostport
    "-L", "127.0.0.1:${lp}:localhost:${rp}"
}

# ---------------------------------------------------------------------------
# SSH invocation (for runner) — builds args and environment, does not start
# ---------------------------------------------------------------------------

function Get-SshInvocationInfo { param([string]$Name)
    $t = Get-TunnelByName -Name $Name
    if (-not $t) { throw "Tunnel '$Name' not found." }
    $ssh = Get-SshPath
    if ([string]::IsNullOrWhiteSpace($t.RemoteHost)) { throw "Tunnel '$Name' has empty RemoteHost. Edit the tunnel to fix." }
    if ([string]::IsNullOrWhiteSpace($t.Username)) { throw "Tunnel '$Name' has empty Username. Edit the tunnel to fix." }
    
    # Determine auth method (default to password for backward compatibility)
    $authMethod = if (-not [string]::IsNullOrWhiteSpace($t.AuthMethod)) { $t.AuthMethod } else { 'password' }
    
    # Get password for SSH_ASKPASS mechanism (only for password auth)
    $pw = $null
    if ($authMethod -eq 'password') {
        $pw = if (-not [string]::IsNullOrWhiteSpace($t.Password)) { $t.Password }
              elseif (-not [string]::IsNullOrWhiteSpace($t.PasswordPlain)) { $t.PasswordPlain }
              elseif (-not [string]::IsNullOrWhiteSpace($t.PasswordEncrypted)) { Get-PlainPassword -Encrypted $t.PasswordEncrypted }
              else { throw "Tunnel '$Name' has no password configured. Edit the tunnel to set a password." }
    }
    
    # Validate identity file for key auth
    if ($authMethod -eq 'key') {
        if ([string]::IsNullOrWhiteSpace($t.IdentityFile)) { 
            throw "Tunnel '$Name' uses key authentication but no identity file is configured." 
        }
        if (-not (Test-Path -LiteralPath $t.IdentityFile)) { 
            throw "Identity file not found: $($t.IdentityFile)" 
        }
    }
    
    $fwd = Get-ForwardArg -Tunnel $t
    
    # Connection timeout (default 30 seconds)
    $timeout = if ($t.ConnectTimeout -gt 0) { [int]$t.ConnectTimeout } else { 30 }
    
    # Build SSH arguments
    # -N: No remote command (just forwarding)
    # -o StrictHostKeyChecking=accept-new: Auto-accept new host keys (like plink's behavior)
    # -o ServerAliveInterval=30: Send keepalive every 30s
    # -o ServerAliveCountMax=3: Disconnect after 3 missed keepalives
    # -o ExitOnForwardFailure=yes: Exit if port forwarding fails
    # -o ConnectTimeout=X: Connection timeout in seconds
    $sshArgs = @(
        '-N',
        '-o', 'StrictHostKeyChecking=accept-new',
        '-o', 'ServerAliveInterval=30',
        '-o', 'ServerAliveCountMax=3',
        '-o', 'ExitOnForwardFailure=yes',
        '-o', "ConnectTimeout=$timeout"
    )
    
    # Add identity file for key authentication
    if ($authMethod -eq 'key' -and -not [string]::IsNullOrWhiteSpace($t.IdentityFile)) {
        $sshArgs += '-i', $t.IdentityFile
        # Disable password auth when using keys
        $sshArgs += '-o', 'PasswordAuthentication=no'
        $sshArgs += '-o', 'BatchMode=yes'
    }
    
    $sshArgs += $fwd
    
    # SSH port (-p for OpenSSH, was -P for plink)
    $sp = [int]$t.SshPort
    if ($sp -gt 0 -and $sp -ne 22) { $sshArgs += '-p', [string]$sp }
    
    # user@host format
    $sshArgs += "$($t.Username)@$($t.RemoteHost)"
    
    @{ 
        FilePath = $ssh
        ArgumentList = $sshArgs
        Password = $pw
        TunnelName = $Name
        AuthMethod = $authMethod
    }
}

# Backward compatibility alias
function Get-PlinkInvocationInfo { param([string]$Name) Get-SshInvocationInfo -Name $Name }

# Create askpass helper script for password authentication
function New-AskPassScript {
    param([string]$Password, [string]$TunnelName)
    
    $safe = $TunnelName -replace '[^\w\-]', '_'
    $askpassPath = Join-Path $env:TEMP "sshx_askpass_${safe}.cmd"
    
    # Create a batch file that echoes the password
    # Using @echo off and echo without newline issues
    $content = "@echo off`r`necho $Password"
    [System.IO.File]::WriteAllText($askpassPath, $content)
    
    return $askpassPath
}

function Remove-AskPassScript {
    param([string]$TunnelName)
    
    $safe = $TunnelName -replace '[^\w\-]', '_'
    $askpassPath = Join-Path $env:TEMP "sshx_askpass_${safe}.cmd"
    
    if (Test-Path $askpassPath) {
        Remove-Item -LiteralPath $askpassPath -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# Start / Stop / Status (Start runs a runner process that restarts plink on failure)
# ---------------------------------------------------------------------------

function Test-PortInUseOnSystem {
    param([int]$Port)
    try {
        $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $Port)
        $listener.Start()
        $listener.Stop()
        return $false  # Port is available
    } catch {
        return $true   # Port is in use
    }
}

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
    
    # Check if local port is already in use on the system
    $localPort = [int]$t.LocalPort
    if (Test-PortInUseOnSystem -Port $localPort) {
        Write-SSHXLog "Local port $localPort is already in use on this system" -Level 'ERROR'
        throw "Cannot start tunnel: local port $localPort is already in use by another process."
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
    $pidFile  = Join-Path $env:TEMP "sshx_${safe}_ssh.pid"
    $statusFile = Join-Path $env:TEMP "sshx_${safe}_status.json"
    if (-not $runnerPid) { 
        Write-SSHXLog "Tunnel '$Name' has no PID, nothing to stop"
        return $false 
    }
    Write-SSHXLog "Setting stop flag and killing processes (runner PID: $runnerPid)"
    [void](New-Item -ItemType Directory -Path $configDir -Force -ErrorAction SilentlyContinue)
    Set-Content -LiteralPath $stopFlag -Value '1' -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $pidFile) {
        $sshPid = $null
        if ([int]::TryParse((Get-Content -LiteralPath $pidFile -Raw -ErrorAction SilentlyContinue).Trim(), [ref]$sshPid)) {
            Write-SSHXLog "Stopping SSH process (PID: $sshPid)"
            Get-Process -Id $sshPid -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
    }
    Get-Process -Id $runnerPid -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $stopFlag -Force -ErrorAction SilentlyContinue
    # Cleanup askpass script and status file
    Remove-AskPassScript -TunnelName $Name
    Remove-Item -LiteralPath $statusFile -Force -ErrorAction SilentlyContinue
    $cfg = Get-TunnelConfig
    foreach ($x in $cfg.Tunnels) { if ($x.Name -eq $Name) { $x.Pid = $null; break } }
    Save-TunnelConfig -Config $cfg
    $true
}

function Test-LocalPortListening {
    param(
        [int]$Port
    )
    
    # Try multiple methods to check if port is listening
    # Method 1: Get-NetTCPConnection (fast, preferred)
    try {
        $listening = @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction Stop)
        if ($listening.Count -gt 0) {
            return $true
        }
    } catch {
        # CIM query may fail if no matches - this is expected, continue to fallback
    }
    
    # Method 2: Try TCP connection test (actually proves the port is accepting connections)
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $result = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
        $success = $result.AsyncWaitHandle.WaitOne(500)  # 500ms timeout
        if ($success) {
            try { $client.EndConnect($result) } catch { }
            $client.Close()
            return $true
        }
        $client.Close()
    } catch {
        # Connection failed - port not listening or refused
    }
    
    # Method 3: Fallback to netstat (slower but universal)
    try {
        $netstat = netstat -an 2>$null | Select-String "^\s*TCP\s+127\.0\.0\.1:$Port\s+.*LISTENING"
        if ($netstat) {
            return $true
        }
        # Also check 0.0.0.0 binding
        $netstat = netstat -an 2>$null | Select-String "^\s*TCP\s+0\.0\.0\.0:$Port\s+.*LISTENING"
        if ($netstat) {
            return $true
        }
    } catch { }
    
    return $false
}

function Get-TunnelStatus { param([string]$Name)
    $t = Get-TunnelByName -Name $Name
    if (-not $t) { return $null }
    $runnerAlive = $false
    $tunnelConnected = $false
    
    if ($t.Pid) {
        $p = Get-Process -Id $t.Pid -ErrorAction SilentlyContinue
        $runnerAlive = $null -ne $p
        if (-not $runnerAlive) {
            $cfg = Get-TunnelConfig
            foreach ($x in $cfg.Tunnels) { if ($x.Name -eq $Name) { $x.Pid = $null; break } }
            Save-TunnelConfig -Config $cfg
            $t.Pid = $null
        }
    }
    
    # Check if the tunnel is actually connected by testing if local port is listening
    if ($runnerAlive -and $t.LocalPort -gt 0) {
        $tunnelConnected = Test-LocalPortListening -Port ([int]$t.LocalPort)
    }
    
    [pscustomobject]@{ 
        Tunnel = $t
        Running = $runnerAlive
        Connected = $tunnelConnected
        Pid = $t.Pid 
    }
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
# Test Connection - Verify SSH credentials before saving
# ---------------------------------------------------------------------------

function Test-SshConnection {
    param(
        [string]$RemoteHost,
        [int]$SshPort = 22,
        [string]$Username,
        [string]$Password,
        [string]$IdentityFile,
        [string]$AuthMethod = 'password',
        [int]$TimeoutSeconds = 10
    )
    
    Write-SSHXLog "Testing connection to $Username@$RemoteHost`:$SshPort (auth: $AuthMethod)"
    
    $ssh = Get-SshPath
    
    # Build SSH arguments for connection test
    # Use a quick command that exits immediately
    $sshArgs = @(
        '-o', 'StrictHostKeyChecking=accept-new',
        '-o', "ConnectTimeout=$TimeoutSeconds",
        '-o', 'BatchMode=yes'
    )
    
    if ($AuthMethod -eq 'key' -and -not [string]::IsNullOrWhiteSpace($IdentityFile)) {
        if (-not (Test-Path -LiteralPath $IdentityFile)) {
            return @{ Success = $false; Message = "Identity file not found: $IdentityFile" }
        }
        $sshArgs += '-i', $IdentityFile
        $sshArgs += '-o', 'PasswordAuthentication=no'
    }
    
    if ($SshPort -ne 22) { $sshArgs += '-p', [string]$SshPort }
    $sshArgs += "$Username@$RemoteHost"
    $sshArgs += 'echo', 'SSHX_TEST_OK'  # Simple command to verify connection
    
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $ssh
        $psi.Arguments = $sshArgs -join ' '
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardError = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardInput = $true
        
        # For password auth, use SSH_ASKPASS
        if ($AuthMethod -eq 'password' -and -not [string]::IsNullOrWhiteSpace($Password)) {
            $askpassPath = New-AskPassScript -Password $Password -TunnelName '__test__'
            $psi.EnvironmentVariables['SSH_ASKPASS'] = $askpassPath
            $psi.EnvironmentVariables['SSH_ASKPASS_REQUIRE'] = 'force'
            $psi.EnvironmentVariables['DISPLAY'] = 'localhost:0'
            # Remove BatchMode for password auth
            $psi.Arguments = $psi.Arguments -replace '-o BatchMode=yes', ''
        }
        
        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $psi
        $proc.Start() | Out-Null
        
        # Wait with timeout
        $exited = $proc.WaitForExit(($TimeoutSeconds + 5) * 1000)
        
        $stdout = $proc.StandardOutput.ReadToEnd()
        $stderr = $proc.StandardError.ReadToEnd()
        
        # Cleanup askpass
        Remove-AskPassScript -TunnelName '__test__'
        
        if (-not $exited) {
            try { $proc.Kill() } catch { }
            Write-SSHXLog "Connection test timed out" -Level 'WARN'
            return @{ Success = $false; Message = "Connection timed out after $TimeoutSeconds seconds" }
        }
        
        if ($proc.ExitCode -eq 0 -and $stdout -match 'SSHX_TEST_OK') {
            Write-SSHXLog "Connection test successful"
            return @{ Success = $true; Message = "Connection successful" }
        } else {
            $errMsg = if ($stderr) { $stderr.Trim() } else { "SSH exited with code $($proc.ExitCode)" }
            Write-SSHXLog "Connection test failed: $errMsg" -Level 'WARN'
            return @{ Success = $false; Message = $errMsg }
        }
    } catch {
        Write-SSHXLog "Connection test error: $_" -Level 'ERROR'
        return @{ Success = $false; Message = $_.ToString() }
    }
}

# ---------------------------------------------------------------------------
# Duplicate Tunnel
# ---------------------------------------------------------------------------

function Copy-Tunnel {
    param(
        [string]$SourceName,
        [string]$NewName,
        [int]$NewLocalPort = 0  # If 0, will auto-increment
    )
    
    $source = Get-TunnelByName -Name $SourceName
    if (-not $source) { throw "Tunnel '$SourceName' not found." }
    
    if ([string]::IsNullOrWhiteSpace($NewName)) {
        # Generate a name like "MyTunnel (copy)" or "MyTunnel (copy 2)"
        $baseName = "$SourceName (copy)"
        $NewName = $baseName
        $counter = 2
        while (Get-TunnelByName -Name $NewName) {
            $NewName = "$SourceName (copy $counter)"
            $counter++
        }
    }
    
    if (Get-TunnelByName -Name $NewName) { throw "Tunnel '$NewName' already exists." }
    
    # Find available local port if not specified
    if ($NewLocalPort -le 0) {
        $NewLocalPort = [int]$source.LocalPort + 1
        $cfg = Get-TunnelConfig
        $usedPorts = $cfg.Tunnels | ForEach-Object { [int]$_.LocalPort }
        while ($usedPorts -contains $NewLocalPort -or (Test-PortInUseOnSystem -Port $NewLocalPort)) {
            $NewLocalPort++
            if ($NewLocalPort -gt 65535) { throw "Could not find available local port." }
        }
    }
    
    Test-LocalPortAvailable -LocalPort $NewLocalPort | Out-Null
    
    Write-SSHXLog "Duplicating tunnel '$SourceName' as '$NewName' (local port: $NewLocalPort)"
    
    # Determine auth method
    $authMethod = if (-not [string]::IsNullOrWhiteSpace($source.AuthMethod)) { $source.AuthMethod } else { 'password' }
    
    $params = @{
        Name = $NewName
        RemoteHost = $source.RemoteHost
        RemotePort = [int]$source.RemotePort
        LocalPort = $NewLocalPort
        Username = $source.Username
        SshPort = if ($source.SshPort -gt 0) { [int]$source.SshPort } else { 22 }
        AuthMethod = $authMethod
        Group = $source.Group
        ConnectTimeout = if ($source.ConnectTimeout -gt 0) { [int]$source.ConnectTimeout } else { 30 }
    }
    
    if ($authMethod -eq 'key') {
        $params['IdentityFile'] = $source.IdentityFile
        $params['PasswordPlain'] = ''  # No password needed for key auth
    } else {
        # Copy encrypted password by directly manipulating config
        $params['PasswordPlain'] = 'placeholder'  # Will be replaced below
    }
    
    $newTunnel = Add-Tunnel @params
    
    # If password auth, copy the encrypted password directly (so user doesn't need to re-enter)
    if ($authMethod -eq 'password' -and -not [string]::IsNullOrWhiteSpace($source.PasswordEncrypted)) {
        $cfg = Get-TunnelConfig
        for ($i = 0; $i -lt $cfg.Tunnels.Count; $i++) {
            if ($cfg.Tunnels[$i].Name -eq $NewName) {
                $cfg.Tunnels[$i].PasswordEncrypted = $source.PasswordEncrypted
                break
            }
        }
        Save-TunnelConfig -Config $cfg
    }
    
    Write-SSHXLog "Tunnel '$NewName' created as copy of '$SourceName'"
    return Get-TunnelByName -Name $NewName
}

# ---------------------------------------------------------------------------
# Group Operations
# ---------------------------------------------------------------------------

function Get-TunnelGroups {
    $tunnels = Get-AllTunnels
    $groups = @{}
    foreach ($t in $tunnels) {
        $groupName = if (-not [string]::IsNullOrWhiteSpace($t.Group)) { $t.Group } else { '(Ungrouped)' }
        if (-not $groups.ContainsKey($groupName)) {
            $groups[$groupName] = @()
        }
        $groups[$groupName] += $t
    }
    return $groups
}

function Get-TunnelsByGroup {
    param([string]$GroupName)
    $tunnels = Get-AllTunnels
    if ($GroupName -eq '(Ungrouped)' -or [string]::IsNullOrWhiteSpace($GroupName)) {
        return @($tunnels | Where-Object { [string]::IsNullOrWhiteSpace($_.Group) })
    }
    return @($tunnels | Where-Object { $_.Group -eq $GroupName })
}

function Start-TunnelGroup {
    param([string]$GroupName)
    Write-SSHXLog "Starting tunnel group: $GroupName"
    $tunnels = Get-TunnelsByGroup -GroupName $GroupName
    $results = @()
    foreach ($t in $tunnels) {
        try {
            # Skip if already running
            $status = Get-TunnelStatus -Name $t.Name
            if ($status.Running) {
                $results += @{ Name = $t.Name; Success = $true; Message = "Already running" }
                continue
            }
            Start-Tunnel -Name $t.Name | Out-Null
            $results += @{ Name = $t.Name; Success = $true; Message = "Started" }
        } catch {
            $results += @{ Name = $t.Name; Success = $false; Message = $_.ToString() }
        }
    }
    return $results
}

function Stop-TunnelGroup {
    param([string]$GroupName)
    Write-SSHXLog "Stopping tunnel group: $GroupName"
    $tunnels = Get-TunnelsByGroup -GroupName $GroupName
    $results = @()
    foreach ($t in $tunnels) {
        try {
            $status = Get-TunnelStatus -Name $t.Name
            if (-not $status.Running) {
                $results += @{ Name = $t.Name; Success = $true; Message = "Already stopped" }
                continue
            }
            Stop-Tunnel -Name $t.Name | Out-Null
            $results += @{ Name = $t.Name; Success = $true; Message = "Stopped" }
        } catch {
            $results += @{ Name = $t.Name; Success = $false; Message = $_.ToString() }
        }
    }
    return $results
}

# ---------------------------------------------------------------------------
# Import/Export Enhanced
# ---------------------------------------------------------------------------

function Import-Tunnels {
    param(
        [string]$FilePath,
        [switch]$SkipExisting,   # Skip tunnels that already exist
        [switch]$ReplaceExisting # Replace tunnels that already exist
    )
    
    if (-not (Test-Path -LiteralPath $FilePath)) {
        throw "Import file not found: $FilePath"
    }
    
    Write-SSHXLog "Importing tunnels from: $FilePath"
    
    try {
        $json = Get-Content -LiteralPath $FilePath -Raw | ConvertFrom-Json
    } catch {
        throw "Invalid JSON file: $_"
    }
    
    # Handle both array format and object with Tunnels property
    $tunnelsToImport = if ($json -is [array]) { $json } 
                       elseif ($json.Tunnels) { $json.Tunnels }
                       else { throw "Invalid tunnel export format" }
    
    $results = @{ Imported = 0; Skipped = 0; Replaced = 0; Errors = @() }
    
    foreach ($t in $tunnelsToImport) {
        if ([string]::IsNullOrWhiteSpace($t.Name)) { 
            $results.Errors += "Skipped tunnel with empty name"
            continue 
        }
        
        $existing = Get-TunnelByName -Name $t.Name
        if ($existing) {
            if ($SkipExisting) {
                $results.Skipped++
                continue
            } elseif ($ReplaceExisting) {
                Remove-Tunnel -Name $t.Name
                $results.Replaced++
            } else {
                $results.Errors += "Tunnel '$($t.Name)' already exists (use -SkipExisting or -ReplaceExisting)"
                continue
            }
        }
        
        try {
            # Note: Passwords are not exported/imported for security
            # User will need to set passwords after import
            $authMethod = if (-not [string]::IsNullOrWhiteSpace($t.AuthMethod)) { $t.AuthMethod } else { 'password' }
            
            $params = @{
                Name = $t.Name
                RemoteHost = $t.RemoteHost
                RemotePort = [int]$t.RemotePort
                LocalPort = [int]$t.LocalPort
                Username = $t.Username
                SshPort = if ($t.SshPort -gt 0) { [int]$t.SshPort } else { 22 }
                AuthMethod = $authMethod
                Group = $t.Group
                ConnectTimeout = if ($t.ConnectTimeout -gt 0) { [int]$t.ConnectTimeout } else { 30 }
            }
            
            if ($authMethod -eq 'key') {
                $params['IdentityFile'] = $t.IdentityFile
            } else {
                # Use a placeholder - user must edit to set real password
                $params['PasswordPlain'] = 'IMPORTED_SET_PASSWORD'
            }
            
            Add-Tunnel @params | Out-Null
            $results.Imported++
        } catch {
            $results.Errors += "Failed to import '$($t.Name)': $_"
        }
    }
    
    Write-SSHXLog "Import complete: $($results.Imported) imported, $($results.Skipped) skipped, $($results.Replaced) replaced, $($results.Errors.Count) errors"
    return $results
}

function Export-TunnelsToFile {
    param(
        [string]$FilePath,
        [string]$GroupName = $null,  # Export specific group only
        [switch]$IncludePasswords    # NOT RECOMMENDED - only for same-user backup
    )
    
    Write-SSHXLog "Exporting tunnels to: $FilePath"
    
    $tunnels = if (-not [string]::IsNullOrWhiteSpace($GroupName)) {
        Get-TunnelsByGroup -GroupName $GroupName
    } else {
        Get-AllTunnels
    }
    
    $exportList = @()
    foreach ($t in $tunnels) {
        $export = [pscustomobject]@{
            Name           = $t.Name
            RemoteHost     = $t.RemoteHost
            RemotePort     = $t.RemotePort
            LocalPort      = $t.LocalPort
            SshPort        = $t.SshPort
            Username       = $t.Username
            AuthMethod     = if ($t.AuthMethod) { $t.AuthMethod } else { 'password' }
            IdentityFile   = $t.IdentityFile
            Group          = $t.Group
            ConnectTimeout = if ($t.ConnectTimeout -gt 0) { $t.ConnectTimeout } else { 30 }
        }
        
        # Only include encrypted password if explicitly requested (same-user backup)
        if ($IncludePasswords -and -not [string]::IsNullOrWhiteSpace($t.PasswordEncrypted)) {
            $export | Add-Member -NotePropertyName 'PasswordEncrypted' -NotePropertyValue $t.PasswordEncrypted
        }
        
        $exportList += $export
    }
    
    $exportList | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $FilePath -Encoding UTF8
    Write-SSHXLog "Exported $($exportList.Count) tunnel(s)"
    return $exportList.Count
}

# ---------------------------------------------------------------------------
# Auto-Start (Windows Startup)
# ---------------------------------------------------------------------------

function Get-StartupShortcutPath {
    $startupFolder = [System.IO.Path]::Combine($env:APPDATA, 'Microsoft\Windows\Start Menu\Programs\Startup')
    return Join-Path $startupFolder 'sshx.lnk'
}

function Test-AutoStartEnabled {
    $shortcutPath = Get-StartupShortcutPath
    return Test-Path -LiteralPath $shortcutPath
}

function Enable-AutoStart {
    param([string]$LauncherPath)  # Path to sshx.vbs
    
    if ([string]::IsNullOrWhiteSpace($LauncherPath)) {
        throw "Launcher path is required"
    }
    if (-not (Test-Path -LiteralPath $LauncherPath)) {
        throw "Launcher not found: $LauncherPath"
    }
    
    $shortcutPath = Get-StartupShortcutPath
    Write-SSHXLog "Enabling auto-start: $shortcutPath"
    
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $LauncherPath
    $shortcut.WorkingDirectory = Split-Path -Parent $LauncherPath
    $shortcut.Description = 'sshx - SSH Tunnel Manager'
    $shortcut.Save()
    
    Write-SSHXLog "Auto-start enabled"
    return $true
}

function Disable-AutoStart {
    $shortcutPath = Get-StartupShortcutPath
    if (Test-Path -LiteralPath $shortcutPath) {
        Write-SSHXLog "Disabling auto-start"
        Remove-Item -LiteralPath $shortcutPath -Force
        return $true
    }
    return $false
}

# ---------------------------------------------------------------------------
# Runner Log Access
# ---------------------------------------------------------------------------

function Get-TunnelLogPath {
    param([string]$TunnelName)
    $safe = $TunnelName -replace '[^\w\-]', '_'
    return Join-Path $env:TEMP "sshx_runner_${safe}.log"
}

function Get-RunnerStatusPath {
    param([string]$TunnelName)
    $safe = $TunnelName -replace '[^\w\-]', '_'
    return Join-Path $env:TEMP "sshx_${safe}_status.json"
}

function Get-RunnerStatus {
    param([string]$TunnelName)
    $statusPath = Get-RunnerStatusPath -TunnelName $TunnelName
    if (-not (Test-Path -LiteralPath $statusPath)) {
        return $null
    }
    try {
        $json = Get-Content -LiteralPath $statusPath -Raw -ErrorAction SilentlyContinue
        if ($json) {
            $status = $json | ConvertFrom-Json
            # Check if status is stale (older than 30 seconds means runner probably died)
            $timestamp = [DateTime]::Parse($status.Timestamp)
            $age = ([DateTime]::Now - $timestamp).TotalSeconds
            if ($age -gt 30) {
                # Status file is stale - runner might be dead
                return @{ Status = 'Unknown'; Detail = 'Status stale'; Age = $age }
            }
            return @{ Status = $status.Status; Detail = $status.Detail; Failures = $status.Failures; Age = $age }
        }
    } catch { }
    return $null
}

function Get-TunnelLog {
    param(
        [string]$TunnelName,
        [int]$TailLines = 100
    )
    $logPath = Get-TunnelLogPath -TunnelName $TunnelName
    if (-not (Test-Path -LiteralPath $logPath)) {
        return @()
    }
    return Get-Content -LiteralPath $logPath -Tail $TailLines
}

function Clear-TunnelLog {
    param([string]$TunnelName)
    $logPath = Get-TunnelLogPath -TunnelName $TunnelName
    if (Test-Path -LiteralPath $logPath) {
        Remove-Item -LiteralPath $logPath -Force
        return $true
    }
    return $false
}

# ---------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------

Export-ModuleMember -Function @(
    'Write-SSHXLog',
    'Get-TunnelConfig','Save-TunnelConfig',
    'Get-EncryptedPassword','Get-PlainPassword',
    'Get-TunnelByName','Get-AllTunnels','Add-Tunnel','Update-Tunnel','Remove-Tunnel','Copy-Tunnel',
    'Get-ForwardArg','Get-SshInvocationInfo','Get-PlinkInvocationInfo','Start-Tunnel','Stop-Tunnel','Get-TunnelStatus','Get-AllTunnelStatuses',
    'Get-SshPath','Get-PlinkPath','Initialize-ConfigDir','Test-HostKeyError',
    'Test-ValidPort','Test-LocalPortAvailable','Test-DuplicateTunnel','Test-PortInUseOnSystem','Test-LocalPortListening',
    'New-AskPassScript','Remove-AskPassScript',
    # New functions
    'Test-SshConnection',
    'Get-TunnelGroups','Get-TunnelsByGroup','Start-TunnelGroup','Stop-TunnelGroup',
    'Import-Tunnels','Export-TunnelsToFile',
    'Get-StartupShortcutPath','Test-AutoStartEnabled','Enable-AutoStart','Disable-AutoStart',
    'Get-TunnelLogPath','Get-TunnelLog','Clear-TunnelLog',
    'Get-RunnerStatusPath','Get-RunnerStatus'
)
