<#
.SYNOPSIS
  Runner that keeps an SSH tunnel (plink) up: restarts plink when it exits (network change, VPN, failure).
  Listens to NetworkAddressChanged and NetworkAvailabilityChanged to kill plink and reconnect immediately.
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
$pidFile       = Join-Path $env:TEMP "sshx_${safe}_plink.pid"
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

Log-Runner "Runner started Name='$Name' (network watcher active)"

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
        exit 0
    }
    $t = Get-TunnelByName -Name $Name
    if (-not $t) { Log-Runner "Tunnel not in config, exiting"; exit 0 }
    try {
        $info = Get-PlinkInvocationInfo -Name $Name
        Log-Runner "Plink: $($info.FilePath), starting"
        $stderrFile = Join-Path $env:TEMP "sshx_plink_${safe}_stderr.txt"
        $proc = Start-Process -FilePath $info.FilePath -ArgumentList $info.ArgumentList -WindowStyle Hidden -PassThru -RedirectStandardError $stderrFile
        $proc.Id | Set-Content -LiteralPath $pidFile
        Log-Runner "Plink started PID $($proc.Id)"
        $proc.WaitForExit()
        $err = Get-Content -LiteralPath $stderrFile -Raw -ErrorAction SilentlyContinue
        if ($err) { Log-Runner "Plink stderr: $($err.Trim())" }
        Remove-Item -LiteralPath $stderrFile -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $restartNowFlag) {
            Remove-Item -LiteralPath $restartNowFlag -Force -ErrorAction SilentlyContinue
            Log-Runner "Plink exited (network/VPN change), reconnecting in 1s"
            Start-Sleep -Seconds 1
        } else {
            Log-Runner "Plink exited code=$($proc.ExitCode), retry in ${retrySec}s"
            Start-Sleep -Seconds $retrySec
        }
    } catch {
        Log-Runner "Error: $_"
        Start-Sleep -Seconds $retrySec
        continue
    }
}
