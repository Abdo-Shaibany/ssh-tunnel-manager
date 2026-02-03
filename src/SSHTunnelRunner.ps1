<#
.SYNOPSIS
  Runner that keeps an SSH tunnel up: restarts ssh when it exits (network change, VPN, failure).
  Uses Windows built-in OpenSSH (ssh.exe) with SSH_ASKPASS for password authentication.
  Listens to NetworkAddressChanged and NetworkAvailabilityChanged to kill ssh and reconnect immediately.
  Exits only when stop flag is set, tunnel removed from config, or PC shutdown/restart.
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

$configDir     = Join-Path $env:APPDATA 'SSHTunnelManager'
$stopFlag      = Join-Path $configDir "stop_${safe}.flag"
$restartNowFlag = Join-Path $configDir "restart_${safe}.flag"
$pidFile       = Join-Path $env:TEMP "sshx_${safe}_ssh.pid"
$retrySec      = 5

# On network/VPN change: kill plink so the loop restarts it quickly (avoids stale connection).
# Use a file flag so the main loop (possibly on another thread) can see it.
$sf = $stopFlag
$pf = $pidFile
$rf = $restartNowFlag
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
try {
    [System.Net.NetworkInformation.NetworkChange]::NetworkAddressChanged += $onNetworkChange
    [System.Net.NetworkInformation.NetworkChange]::NetworkAvailabilityChanged += $onNetworkChange
} catch { Log-Runner "NetworkChange registration failed: $_" }

Log-Runner "Runner started Name='$Name' (network watcher active, using OpenSSH)"

while ($true) {
    if (Test-Path -LiteralPath $stopFlag) {
        Log-Runner "Stop flag found, exiting"
        Remove-Item -LiteralPath $stopFlag -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $restartNowFlag -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $pidFile) {
            $p = (Get-Content -LiteralPath $pidFile -Raw -ErrorAction SilentlyContinue).Trim()
            if ($p) { Get-Process -Id $p -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue }
        }
        Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
        Remove-AskPassScript -TunnelName $Name
        exit 0
    }
    $t = Get-TunnelByName -Name $Name
    if (-not $t) { 
        Log-Runner "Tunnel not in config, exiting"
        Remove-AskPassScript -TunnelName $Name
        exit 0 
    }
    try {
        $info = Get-SshInvocationInfo -Name $Name
        Log-Runner "SSH: $($info.FilePath), starting tunnel"
        
        # Create askpass script for password authentication
        $askpassPath = New-AskPassScript -Password $info.Password -TunnelName $Name
        Log-Runner "Created askpass helper at: $askpassPath"
        
        $stderrFile = Join-Path $env:TEMP "sshx_ssh_${safe}_stderr.txt"
        
        # Start SSH with ASKPASS environment variables
        # SSH_ASKPASS: path to script that outputs password
        # DISPLAY: must be set (any value) for SSH_ASKPASS to work in non-TTY mode
        # SSH_ASKPASS_REQUIRE: force use of askpass even without TTY (OpenSSH 8.4+)
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $info.FilePath
        $psi.Arguments = $info.ArgumentList -join ' '
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardError = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardInput = $true
        $psi.EnvironmentVariables['SSH_ASKPASS'] = $askpassPath
        $psi.EnvironmentVariables['SSH_ASKPASS_REQUIRE'] = 'force'
        $psi.EnvironmentVariables['DISPLAY'] = 'localhost:0'
        
        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $psi
        $proc.Start() | Out-Null
        
        $proc.Id | Set-Content -LiteralPath $pidFile
        Log-Runner "SSH started PID $($proc.Id)"
        
        # Wait for process to exit
        $proc.WaitForExit()
        
        # Capture stderr
        $err = $proc.StandardError.ReadToEnd()
        if ($err) { Log-Runner "SSH stderr: $($err.Trim())" }
        
        # Cleanup
        Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
        Remove-AskPassScript -TunnelName $Name
        
        if (Test-Path -LiteralPath $restartNowFlag) {
            Remove-Item -LiteralPath $restartNowFlag -Force -ErrorAction SilentlyContinue
            Log-Runner "SSH exited (network/VPN change), reconnecting in 1s"
            Start-Sleep -Seconds 1
        } else {
            Log-Runner "SSH exited code=$($proc.ExitCode), retry in ${retrySec}s"
            Start-Sleep -Seconds $retrySec
        }
    } catch {
        Log-Runner "Error: $_"
        Remove-AskPassScript -TunnelName $Name
        Start-Sleep -Seconds $retrySec
        continue
    }
}
