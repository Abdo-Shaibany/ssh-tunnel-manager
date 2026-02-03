<#
.SYNOPSIS
  Runner that keeps an SSH tunnel up: restarts ssh when it exits (network change, VPN, failure).
  Uses Windows built-in OpenSSH (ssh.exe) with SSH_ASKPASS for password authentication.
  Supports SSH key authentication (no password needed).
  Listens to NetworkAddressChanged and NetworkAvailabilityChanged to kill ssh and reconnect immediately.
  Exits only when stop flag is set, tunnel removed from config, or PC shutdown/restart.
  Uses exponential backoff for retries (5s -> 10s -> 20s -> 40s -> 60s max).
  Logs to %TEMP%\sshx_runner_<name>.log for debugging.
#>
param([string]$Name)
$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $PSCommandPath
$safe      = $Name -replace '[^\w\-]', '_'
$logFile   = Join-Path $env:TEMP "sshx_runner_${safe}.log"

function Log-Runner { param([string]$m)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$ts $m" | Add-Content -LiteralPath $logFile -ErrorAction SilentlyContinue
}

try {
    Import-Module (Join-Path $scriptDir 'SSHTunnelCore.psm1') -Force
} catch {
    Log-Runner "Import-Module failed: $_"
    throw
}

$configDir      = Join-Path $env:APPDATA 'SSHTunnelManager'
$stopFlag       = Join-Path $configDir "stop_${safe}.flag"
$restartNowFlag = Join-Path $configDir "restart_${safe}.flag"
$pidFile        = Join-Path $env:TEMP "sshx_${safe}_ssh.pid"
$statusFile     = Join-Path $env:TEMP "sshx_${safe}_status.json"

# Status tracking - helps UI know what the runner is doing
function Set-RunnerStatus {
    param([string]$Status, [string]$Detail = '')
    try {
        $statusData = @{
            Status = $Status
            Detail = $Detail
            Timestamp = (Get-Date).ToString('o')
            Failures = $consecutiveFailures
        }
        $statusData | ConvertTo-Json | Set-Content -LiteralPath $statusFile -Force -ErrorAction SilentlyContinue
    } catch { }
}

function Remove-RunnerStatus {
    try {
        if (Test-Path -LiteralPath $statusFile) {
            Remove-Item -LiteralPath $statusFile -Force -ErrorAction SilentlyContinue
        }
    } catch { }
}

# Exponential backoff settings
$retryBaseMs     = 5000   # Start at 5 seconds
$retryMaxMs      = 60000  # Max 60 seconds
$retryMultiplier = 2      # Double each time
$currentRetryMs  = $retryBaseMs
$consecutiveFailures = 0

# On network/VPN change: kill ssh so the loop restarts it quickly (avoids stale connection).
# Use a file flag so the main loop (possibly on another thread) can see it.
$sf = $stopFlag
$pf = $pidFile
$rf = $restartNowFlag
$networkWatcherActive = $false

$onNetworkChange = {
    if (Test-Path -LiteralPath $sf) { return }
    try {
        [System.IO.File]::WriteAllText($rf, '1')
        if (Test-Path -LiteralPath $pf) {
            $p = (Get-Content -LiteralPath $pf -Raw -ErrorAction SilentlyContinue).Trim()
            if ($p) { Get-Process -Id $p -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue }
            Remove-Item -LiteralPath $pf -Force -ErrorAction SilentlyContinue
        }
    } catch { }
}

# Try to register network change events (may fail on some systems)
try {
    # Method 1: Direct event handler (works in most PowerShell versions)
    $networkType = [System.Net.NetworkInformation.NetworkChange]
    Register-ObjectEvent -InputObject $networkType -EventName 'NetworkAddressChanged' -Action $onNetworkChange -ErrorAction Stop | Out-Null
    Register-ObjectEvent -InputObject $networkType -EventName 'NetworkAvailabilityChanged' -Action $onNetworkChange -ErrorAction Stop | Out-Null
    $networkWatcherActive = $true
    Log-Runner "Network watcher registered successfully"
} catch {
    # Method 2: Alternative syntax for older PowerShell
    try {
        [System.Net.NetworkInformation.NetworkChange]::add_NetworkAddressChanged($onNetworkChange)
        [System.Net.NetworkInformation.NetworkChange]::add_NetworkAvailabilityChanged($onNetworkChange)
        $networkWatcherActive = $true
        Log-Runner "Network watcher registered (alternative method)"
    } catch {
        Log-Runner "NetworkChange registration failed: $_ (tunnel will still auto-reconnect on SSH failure)"
    }
}

$watcherStatus = if ($networkWatcherActive) { "network watcher active" } else { "network watcher unavailable" }
Log-Runner "Runner started Name='$Name' ($watcherStatus, using OpenSSH, exponential backoff enabled)"

Set-RunnerStatus -Status 'Starting' -Detail 'Initializing'

while ($true) {
    if (Test-Path -LiteralPath $stopFlag) {
        Log-Runner "Stop flag found, exiting"
        Set-RunnerStatus -Status 'Stopping'
        Remove-Item -LiteralPath $stopFlag -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $restartNowFlag -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $pidFile) {
            $p = (Get-Content -LiteralPath $pidFile -Raw -ErrorAction SilentlyContinue).Trim()
            if ($p) { Get-Process -Id $p -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue }
        }
        Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
        Remove-AskPassScript -TunnelName $Name
        Remove-RunnerStatus
        exit 0
    }
    $t = Get-TunnelByName -Name $Name
    if (-not $t) { 
        Log-Runner "Tunnel not in config, exiting"
        Remove-AskPassScript -TunnelName $Name
        Remove-RunnerStatus
        exit 0 
    }
    try {
        Set-RunnerStatus -Status 'Connecting' -Detail "Attempt #$($consecutiveFailures + 1)"
        $info = Get-SshInvocationInfo -Name $Name
        $authMethod = if ($info.AuthMethod) { $info.AuthMethod } else { 'password' }
        Log-Runner "SSH: $($info.FilePath), starting tunnel (auth: $authMethod)"
        
        $stderrFile = Join-Path $env:TEMP "sshx_ssh_${safe}_stderr.txt"
        
        # Start SSH process
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $info.FilePath
        $psi.Arguments = $info.ArgumentList -join ' '
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardError = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardInput = $true
        
        # Only set up password auth if using password method
        if ($authMethod -eq 'password' -and $info.Password) {
            # Create askpass script for password authentication
            $askpassPath = New-AskPassScript -Password $info.Password -TunnelName $Name
            Log-Runner "Created askpass helper at: $askpassPath"
            
            # SSH_ASKPASS: path to script that outputs password
            # DISPLAY: must be set (any value) for SSH_ASKPASS to work in non-TTY mode
            # SSH_ASKPASS_REQUIRE: force use of askpass even without TTY (OpenSSH 8.4+)
            $psi.EnvironmentVariables['SSH_ASKPASS'] = $askpassPath
            $psi.EnvironmentVariables['SSH_ASKPASS_REQUIRE'] = 'force'
            $psi.EnvironmentVariables['DISPLAY'] = 'localhost:0'
        } else {
            Log-Runner "Using SSH key authentication (no password)"
        }
        
        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $psi
        $proc.Start() | Out-Null
        
        $proc.Id | Set-Content -LiteralPath $pidFile
        Log-Runner "SSH started PID $($proc.Id)"
        
        # Track when the connection started
        $connectionStart = [DateTime]::Now
        $localPort = [int]$t.LocalPort
        $wasConnected = $false
        
        # Wait a moment for SSH to establish, then mark as connected
        Start-Sleep -Milliseconds 2000
        
        # Poll for process exit while updating status periodically
        $lastStatusUpdate = [DateTime]::Now
        while (-not $proc.HasExited) {
            # Check if port is listening
            if ($localPort -gt 0 -and (Test-LocalPortListening -Port $localPort)) {
                if (-not $wasConnected) {
                    Log-Runner "Tunnel connected (port $localPort listening)"
                    $consecutiveFailures = 0  # Reset on successful connection
                    $wasConnected = $true
                }
                # Update status every 10 seconds to keep it fresh
                if (([DateTime]::Now - $lastStatusUpdate).TotalSeconds -ge 10) {
                    Set-RunnerStatus -Status 'Connected' -Detail "PID $($proc.Id), uptime $([int]([DateTime]::Now - $connectionStart).TotalSeconds)s"
                    $lastStatusUpdate = [DateTime]::Now
                }
            } elseif ($wasConnected) {
                # Was connected but port no longer listening - might be brief hiccup
                Set-RunnerStatus -Status 'Reconnecting' -Detail 'Port check failed'
            }
            
            # Check for stop flag
            if (Test-Path -LiteralPath $stopFlag) {
                Log-Runner "Stop flag detected, killing SSH"
                try { $proc.Kill() } catch { }
                break
            }
            
            # Check for restart flag
            if (Test-Path -LiteralPath $restartNowFlag) {
                Log-Runner "Restart flag detected, killing SSH"
                try { $proc.Kill() } catch { }
                break
            }
            
            Start-Sleep -Milliseconds 1000
        }
        
        # Ensure process has exited
        if (-not $proc.HasExited) {
            $proc.WaitForExit(5000)
        }
        
        # Calculate how long the connection was up
        $connectionDuration = ([DateTime]::Now - $connectionStart).TotalSeconds
        
        # Capture stderr
        $err = $proc.StandardError.ReadToEnd()
        if ($err) { Log-Runner "SSH stderr: $($err.Trim())" }
        
        # Cleanup
        Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
        Remove-AskPassScript -TunnelName $Name
        
        if (Test-Path -LiteralPath $restartNowFlag) {
            # Network change - reset backoff and reconnect quickly
            Remove-Item -LiteralPath $restartNowFlag -Force -ErrorAction SilentlyContinue
            Log-Runner "SSH exited (network/VPN change), reconnecting in 1s"
            Set-RunnerStatus -Status 'Reconnecting' -Detail 'Network change detected'
            $currentRetryMs = $retryBaseMs  # Reset backoff
            $consecutiveFailures = 0
            Start-Sleep -Seconds 1
        } else {
            # Normal exit or failure
            # If connection was up for more than 60 seconds, reset backoff (it was working)
            if ($connectionDuration -gt 60) {
                Log-Runner "Connection was stable for $([int]$connectionDuration)s, resetting backoff"
                $currentRetryMs = $retryBaseMs
                $consecutiveFailures = 0
                Set-RunnerStatus -Status 'Reconnecting' -Detail 'Connection dropped, reconnecting'
            } else {
                $consecutiveFailures++
                Set-RunnerStatus -Status 'Failing' -Detail "Attempt #$consecutiveFailures, exit code $($proc.ExitCode)"
            }
            
            $retrySec = [math]::Round($currentRetryMs / 1000, 1)
            Log-Runner "SSH exited code=$($proc.ExitCode) after $([int]$connectionDuration)s, retry #$consecutiveFailures in ${retrySec}s"
            Start-Sleep -Milliseconds $currentRetryMs
            
            # Increase backoff for next failure (exponential)
            $currentRetryMs = [math]::Min($currentRetryMs * $retryMultiplier, $retryMaxMs)
        }
    } catch {
        Log-Runner "Error: $_"
        Remove-AskPassScript -TunnelName $Name
        
        $consecutiveFailures++
        $retrySec = [math]::Round($currentRetryMs / 1000, 1)
        Log-Runner "Retry #$consecutiveFailures in ${retrySec}s"
        Start-Sleep -Milliseconds $currentRetryMs
        
        # Increase backoff
        $currentRetryMs = [math]::Min($currentRetryMs * $retryMultiplier, $retryMaxMs)
        continue
    }
}
