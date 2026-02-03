<#
.SYNOPSIS
  sshx — SSH Tunnel Manager with full CRUD operations.
  Features: SSH key & password auth, groups, log viewer.
  Tunnels auto-reconnect on network/VPN changes; they only stop when you stop them or the PC shuts down.
  Usage: .\sshx.ps1
#>

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles() | Out-Null

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $ScriptDir 'SSHTunnelCore.psm1') -Force

Write-SSHXLog "=== sshx starting ==="

# Global variables
$script:mainForm = $null

# ---------------------------------------------------------------------------
# Intro: Simple "sshx" title with subtitle
# ---------------------------------------------------------------------------

$introDurationMs = 2000

function New-IntroForm {
    $f = New-Object System.Windows.Forms.Form
    $f.FormBorderStyle = 'None'
    $f.BackColor = [System.Drawing.Color]::FromArgb(20, 20, 25)
    $f.Size = New-Object System.Drawing.Size(400, 180)
    $f.StartPosition = 'CenterScreen'
    $f.Topmost = $true
    $f.KeyPreview = $true

    $pnl = New-Object System.Windows.Forms.Panel
    $pnl.Dock = 'Fill'
    $pnl.BackColor = [System.Drawing.Color]::FromArgb(20, 20, 25)
    try {
        $tp = $pnl.GetType(); $dp = $tp.GetProperty('DoubleBuffered', [Reflection.BindingFlags]::NonPublic -bor [Reflection.BindingFlags]::Instance)
        if ($dp) { $dp.SetValue($pnl, $true, $null) }
    } catch { }
    $f.Controls.Add($pnl)

    $pnl.Add_Paint({
        param($sender, $e)
        $g = $e.Graphics
        $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit
        $g.Clear([System.Drawing.Color]::FromArgb(20, 20, 25))

        $cx = $sender.Width / 2
        $cy = $sender.Height / 2

        # Main title: sshx
        $titleFont = New-Object System.Drawing.Font('Segoe UI', 48, [System.Drawing.FontStyle]::Bold)
        $title = 'sshx'
        $titleSize = $g.MeasureString($title, $titleFont)
        $titleX = $cx - ($titleSize.Width / 2)
        $titleY = $cy - $titleSize.Height + 10
        $g.DrawString($title, $titleFont, [System.Drawing.Brushes]::White, [float]$titleX, [float]$titleY)
        $titleFont.Dispose()

        # Subtitle
        $subFont = New-Object System.Drawing.Font('Segoe UI', 12)
        $subtitle = 'SSH Tunnel Manager'
        $subSize = $g.MeasureString($subtitle, $subFont)
        $subX = $cx - ($subSize.Width / 2)
        $subY = $cy + 15
        $grayBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(150, 150, 150))
        $g.DrawString($subtitle, $subFont, $grayBrush, [float]$subX, [float]$subY)
        $grayBrush.Dispose()
        $subFont.Dispose()
    })

    $done = $false
    $checkEnd = New-Object System.Windows.Forms.Timer
    $checkEnd.Interval = 100
    $closeIntro = {
        if ($script:done) { return }
        $script:done = $true
        try { $checkEnd.Stop(); $checkEnd.Dispose() } catch { }
        $f.DialogResult = 'OK'
        $f.Close()
    }

    $f.Add_KeyDown({ & $closeIntro })
    $f.Add_Click({ & $closeIntro })
    $pnl.Add_Click({ & $closeIntro })

    $start = [Environment]::TickCount
    $checkEnd.Add_Tick({
        if (([Environment]::TickCount - $start) -ge $introDurationMs) { & $closeIntro }
    })
    $checkEnd.Start()

    $f.ShowDialog() | Out-Null
}

# ---------------------------------------------------------------------------
# Add/Edit Tunnel Dialog (Enhanced with SSH key, group, timeout, test)
# ---------------------------------------------------------------------------

function Show-TunnelDialog {
    param(
        [string]$Title = 'Add Tunnel',
        [object]$Tunnel = $null  # null for Add, existing tunnel for Edit
    )
    
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = $Title
    $dlg.Size = New-Object System.Drawing.Size(480, 520)
    $dlg.StartPosition = 'CenterParent'
    $dlg.FormBorderStyle = 'FixedDialog'
    $dlg.MaximizeBox = $false
    $dlg.MinimizeBox = $false
    
    $y = 15
    $lblWidth = 110
    $txtWidth = 320
    $leftMargin = 15
    $inputX = 130
    
    # --- Basic Settings ---
    $lblBasic = New-Object System.Windows.Forms.Label
    $lblBasic.Text = 'Basic Settings'
    $lblBasic.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $lblBasic.Location = New-Object System.Drawing.Point($leftMargin, $y)
    $lblBasic.Size = New-Object System.Drawing.Size(200, 18)
    $dlg.Controls.Add($lblBasic)
    $y += 22
    
    # Name
    $lblName = New-Object System.Windows.Forms.Label
    $lblName.Text = 'Name:'
    $lblName.Location = New-Object System.Drawing.Point($leftMargin, $y)
    $lblName.Size = New-Object System.Drawing.Size($lblWidth, 20)
    $dlg.Controls.Add($lblName)
    
    $txtName = New-Object System.Windows.Forms.TextBox
    $txtName.Location = New-Object System.Drawing.Point($inputX, $y)
    $txtName.Size = New-Object System.Drawing.Size($txtWidth, 20)
    if ($Tunnel) { $txtName.Text = $Tunnel.Name }
    $dlg.Controls.Add($txtName)
    $y += 28
    
    # Group
    $lblGroup = New-Object System.Windows.Forms.Label
    $lblGroup.Text = 'Group (optional):'
    $lblGroup.Location = New-Object System.Drawing.Point($leftMargin, $y)
    $lblGroup.Size = New-Object System.Drawing.Size($lblWidth, 20)
    $dlg.Controls.Add($lblGroup)
    
    $cboGroup = New-Object System.Windows.Forms.ComboBox
    $cboGroup.Location = New-Object System.Drawing.Point($inputX, $y)
    $cboGroup.Size = New-Object System.Drawing.Size(150, 20)
    $cboGroup.DropDownStyle = 'DropDown'  # Allow typing new groups
    # Populate with existing groups
    $existingGroups = (Get-TunnelGroups).Keys | Where-Object { $_ -ne '(Ungrouped)' } | Sort-Object
    foreach ($g in $existingGroups) { $cboGroup.Items.Add($g) | Out-Null }
    if ($Tunnel -and $Tunnel.Group) { $cboGroup.Text = $Tunnel.Group }
    $dlg.Controls.Add($cboGroup)
    $y += 28
    
    # --- Connection Settings ---
    $lblConn = New-Object System.Windows.Forms.Label
    $lblConn.Text = 'Connection'
    $lblConn.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $lblConn.Location = New-Object System.Drawing.Point($leftMargin, $y)
    $lblConn.Size = New-Object System.Drawing.Size(200, 18)
    $dlg.Controls.Add($lblConn)
    $y += 22
    
    # Remote Host
    $lblHost = New-Object System.Windows.Forms.Label
    $lblHost.Text = 'Remote Host:'
    $lblHost.Location = New-Object System.Drawing.Point($leftMargin, $y)
    $lblHost.Size = New-Object System.Drawing.Size($lblWidth, 20)
    $dlg.Controls.Add($lblHost)
    
    $txtHost = New-Object System.Windows.Forms.TextBox
    $txtHost.Location = New-Object System.Drawing.Point($inputX, $y)
    $txtHost.Size = New-Object System.Drawing.Size($txtWidth, 20)
    if ($Tunnel) { $txtHost.Text = $Tunnel.RemoteHost }
    $dlg.Controls.Add($txtHost)
    $y += 28
    
    # Ports row
    $lblRemotePort = New-Object System.Windows.Forms.Label
    $lblRemotePort.Text = 'Remote Port:'
    $lblRemotePort.Location = New-Object System.Drawing.Point($leftMargin, $y)
    $lblRemotePort.Size = New-Object System.Drawing.Size($lblWidth, 20)
    $dlg.Controls.Add($lblRemotePort)
    
    $txtRemotePort = New-Object System.Windows.Forms.TextBox
    $txtRemotePort.Location = New-Object System.Drawing.Point($inputX, $y)
    $txtRemotePort.Size = New-Object System.Drawing.Size(70, 20)
    if ($Tunnel) { $txtRemotePort.Text = [string]$Tunnel.RemotePort }
    $dlg.Controls.Add($txtRemotePort)
    
    $lblLocalPort = New-Object System.Windows.Forms.Label
    $lblLocalPort.Text = 'Local Port:'
    $lblLocalPort.Location = New-Object System.Drawing.Point(220, $y)
    $lblLocalPort.Size = New-Object System.Drawing.Size(70, 20)
    $dlg.Controls.Add($lblLocalPort)
    
    $txtLocalPort = New-Object System.Windows.Forms.TextBox
    $txtLocalPort.Location = New-Object System.Drawing.Point(295, $y)
    $txtLocalPort.Size = New-Object System.Drawing.Size(70, 20)
    if ($Tunnel) { $txtLocalPort.Text = [string]$Tunnel.LocalPort }
    $dlg.Controls.Add($txtLocalPort)
    
    $lblSshPort = New-Object System.Windows.Forms.Label
    $lblSshPort.Text = 'SSH:'
    $lblSshPort.Location = New-Object System.Drawing.Point(375, $y)
    $lblSshPort.Size = New-Object System.Drawing.Size(35, 20)
    $dlg.Controls.Add($lblSshPort)
    
    $txtSshPort = New-Object System.Windows.Forms.TextBox
    $txtSshPort.Location = New-Object System.Drawing.Point(410, $y)
    $txtSshPort.Size = New-Object System.Drawing.Size(45, 20)
    $txtSshPort.Text = if ($Tunnel -and $Tunnel.SshPort) { [string]$Tunnel.SshPort } else { '22' }
    $dlg.Controls.Add($txtSshPort)
    $y += 28
    
    # Timeout
    $lblTimeout = New-Object System.Windows.Forms.Label
    $lblTimeout.Text = 'Connect Timeout:'
    $lblTimeout.Location = New-Object System.Drawing.Point($leftMargin, $y)
    $lblTimeout.Size = New-Object System.Drawing.Size($lblWidth, 20)
    $dlg.Controls.Add($lblTimeout)
    
    $numTimeout = New-Object System.Windows.Forms.NumericUpDown
    $numTimeout.Location = New-Object System.Drawing.Point($inputX, $y)
    $numTimeout.Size = New-Object System.Drawing.Size(70, 20)
    $numTimeout.Minimum = 5
    $numTimeout.Maximum = 300
    $numTimeout.Value = if ($Tunnel -and $Tunnel.ConnectTimeout -gt 0) { $Tunnel.ConnectTimeout } else { 30 }
    $dlg.Controls.Add($numTimeout)
    
    $lblTimeoutSec = New-Object System.Windows.Forms.Label
    $lblTimeoutSec.Text = 'seconds'
    $lblTimeoutSec.Location = New-Object System.Drawing.Point(205, $y)
    $lblTimeoutSec.Size = New-Object System.Drawing.Size(60, 20)
    $lblTimeoutSec.ForeColor = [System.Drawing.Color]::Gray
    $dlg.Controls.Add($lblTimeoutSec)
    $y += 32
    
    # --- Authentication ---
    $lblAuth = New-Object System.Windows.Forms.Label
    $lblAuth.Text = 'Authentication'
    $lblAuth.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $lblAuth.Location = New-Object System.Drawing.Point($leftMargin, $y)
    $lblAuth.Size = New-Object System.Drawing.Size(200, 18)
    $dlg.Controls.Add($lblAuth)
    $y += 22
    
    # Username
    $lblUser = New-Object System.Windows.Forms.Label
    $lblUser.Text = 'Username:'
    $lblUser.Location = New-Object System.Drawing.Point($leftMargin, $y)
    $lblUser.Size = New-Object System.Drawing.Size($lblWidth, 20)
    $dlg.Controls.Add($lblUser)
    
    $txtUser = New-Object System.Windows.Forms.TextBox
    $txtUser.Location = New-Object System.Drawing.Point($inputX, $y)
    $txtUser.Size = New-Object System.Drawing.Size(200, 20)
    if ($Tunnel) { $txtUser.Text = $Tunnel.Username }
    $dlg.Controls.Add($txtUser)
    $y += 28
    
    # Auth method radio buttons
    $lblMethod = New-Object System.Windows.Forms.Label
    $lblMethod.Text = 'Auth Method:'
    $lblMethod.Location = New-Object System.Drawing.Point($leftMargin, $y)
    $lblMethod.Size = New-Object System.Drawing.Size($lblWidth, 20)
    $dlg.Controls.Add($lblMethod)
    
    $radPassword = New-Object System.Windows.Forms.RadioButton
    $radPassword.Text = 'Password'
    $radPassword.Location = New-Object System.Drawing.Point($inputX, $y)
    $radPassword.Size = New-Object System.Drawing.Size(85, 20)
    $dlg.Controls.Add($radPassword)
    
    $radKey = New-Object System.Windows.Forms.RadioButton
    $radKey.Text = 'SSH Key'
    $radKey.Location = New-Object System.Drawing.Point(220, $y)
    $radKey.Size = New-Object System.Drawing.Size(80, 20)
    $dlg.Controls.Add($radKey)
    
    # Default selection
    $authMethod = if ($Tunnel -and $Tunnel.AuthMethod -eq 'key') { 'key' } else { 'password' }
    if ($authMethod -eq 'key') { $radKey.Checked = $true } else { $radPassword.Checked = $true }
    $y += 28
    
    # Password field
    $lblPass = New-Object System.Windows.Forms.Label
    $lblPass.Text = 'Password:'
    $lblPass.Location = New-Object System.Drawing.Point($leftMargin, $y)
    $lblPass.Size = New-Object System.Drawing.Size($lblWidth, 20)
    $dlg.Controls.Add($lblPass)
    
    $txtPass = New-Object System.Windows.Forms.TextBox
    $txtPass.Location = New-Object System.Drawing.Point($inputX, $y)
    $txtPass.Size = New-Object System.Drawing.Size($txtWidth, 20)
    $txtPass.UseSystemPasswordChar = $true
    $dlg.Controls.Add($txtPass)
    $y += 22
    
    $lblPassHint = New-Object System.Windows.Forms.Label
    $lblPassHint.Text = if ($Tunnel) { '(leave blank to keep existing)' } else { '' }
    $lblPassHint.Location = New-Object System.Drawing.Point($inputX, $y)
    $lblPassHint.Size = New-Object System.Drawing.Size($txtWidth, 15)
    $lblPassHint.ForeColor = [System.Drawing.Color]::Gray
    $lblPassHint.Font = New-Object System.Drawing.Font('Segoe UI', 8)
    $dlg.Controls.Add($lblPassHint)
    $y += 22
    
    # SSH Key field
    $lblKeyFile = New-Object System.Windows.Forms.Label
    $lblKeyFile.Text = 'SSH Key File:'
    $lblKeyFile.Location = New-Object System.Drawing.Point($leftMargin, $y)
    $lblKeyFile.Size = New-Object System.Drawing.Size($lblWidth, 20)
    $dlg.Controls.Add($lblKeyFile)
    
    $txtKeyFile = New-Object System.Windows.Forms.TextBox
    $txtKeyFile.Location = New-Object System.Drawing.Point($inputX, $y)
    $txtKeyFile.Size = New-Object System.Drawing.Size(260, 20)
    if ($Tunnel -and $Tunnel.IdentityFile) { $txtKeyFile.Text = $Tunnel.IdentityFile }
    $dlg.Controls.Add($txtKeyFile)
    
    $btnBrowseKey = New-Object System.Windows.Forms.Button
    $btnBrowseKey.Text = '...'
    $btnBrowseKey.Location = New-Object System.Drawing.Point(395, ($y - 1))
    $btnBrowseKey.Size = New-Object System.Drawing.Size(30, 22)
    $btnBrowseKey.Add_Click({
        $ofd = New-Object System.Windows.Forms.OpenFileDialog
        $ofd.Title = 'Select SSH Private Key'
        $ofd.Filter = 'All files (*.*)|*.*|PEM files (*.pem)|*.pem|Key files (*.key)|*.key'
        # Default to .ssh folder
        $sshDir = Join-Path $env:USERPROFILE '.ssh'
        if (Test-Path $sshDir) { $ofd.InitialDirectory = $sshDir }
        if ($ofd.ShowDialog() -eq 'OK') {
            $txtKeyFile.Text = $ofd.FileName
        }
    })
    $dlg.Controls.Add($btnBrowseKey)
    
    $btnOpenSshDir = New-Object System.Windows.Forms.Button
    $btnOpenSshDir.Text = '.ssh'
    $btnOpenSshDir.Location = New-Object System.Drawing.Point(428, ($y - 1))
    $btnOpenSshDir.Size = New-Object System.Drawing.Size(35, 22)
    $btnOpenSshDir.Add_Click({
        $sshDir = Join-Path $env:USERPROFILE '.ssh'
        if (Test-Path $sshDir) {
            Start-Process explorer.exe -ArgumentList $sshDir
        } else {
            [System.Windows.Forms.MessageBox]::Show("SSH directory not found: $sshDir", 'sshx', 'OK', 'Information') | Out-Null
        }
    })
    $dlg.Controls.Add($btnOpenSshDir)
    $y += 35
    
    # Toggle visibility based on auth method
    $updateAuthFields = {
        $isPassword = $radPassword.Checked
        $txtPass.Enabled = $isPassword
        $lblPass.Enabled = $isPassword
        $lblPassHint.Visible = $isPassword
        $txtKeyFile.Enabled = -not $isPassword
        $lblKeyFile.Enabled = -not $isPassword
        $btnBrowseKey.Enabled = -not $isPassword
        $btnOpenSshDir.Enabled = -not $isPassword
    }
    $radPassword.Add_CheckedChanged($updateAuthFields)
    $radKey.Add_CheckedChanged($updateAuthFields)
    & $updateAuthFields  # Initial state
    
    # --- Buttons ---
    $btnTest = New-Object System.Windows.Forms.Button
    $btnTest.Text = 'Test Connection'
    $btnTest.Location = New-Object System.Drawing.Point($leftMargin, $y)
    $btnTest.Size = New-Object System.Drawing.Size(110, 28)
    $btnTest.Add_Click({
        # Gather current form values
        $testHost = $txtHost.Text.Trim()
        $testUser = $txtUser.Text.Trim()
        $testSshPort = 22
        [int]::TryParse($txtSshPort.Text.Trim(), [ref]$testSshPort) | Out-Null
        if ($testSshPort -eq 0) { $testSshPort = 22 }
        $testAuthMethod = if ($radKey.Checked) { 'key' } else { 'password' }
        $testPassword = $txtPass.Text
        $testKeyFile = $txtKeyFile.Text.Trim()
        $testTimeout = [int]$numTimeout.Value
        
        # Validate
        if ([string]::IsNullOrWhiteSpace($testHost)) {
            [System.Windows.Forms.MessageBox]::Show('Enter a Remote Host first.', 'Test Connection', 'OK', 'Warning') | Out-Null
            return
        }
        if ([string]::IsNullOrWhiteSpace($testUser)) {
            [System.Windows.Forms.MessageBox]::Show('Enter a Username first.', 'Test Connection', 'OK', 'Warning') | Out-Null
            return
        }
        if ($testAuthMethod -eq 'password' -and [string]::IsNullOrWhiteSpace($testPassword)) {
            # For edit, we might not have password - need existing
            if ($Tunnel -and $Tunnel.PasswordEncrypted) {
                $testPassword = Get-PlainPassword -Encrypted $Tunnel.PasswordEncrypted
            } else {
                [System.Windows.Forms.MessageBox]::Show('Enter a Password to test.', 'Test Connection', 'OK', 'Warning') | Out-Null
                return
            }
        }
        if ($testAuthMethod -eq 'key' -and [string]::IsNullOrWhiteSpace($testKeyFile)) {
            [System.Windows.Forms.MessageBox]::Show('Select an SSH Key file first.', 'Test Connection', 'OK', 'Warning') | Out-Null
            return
        }
        
        $btnTest.Enabled = $false
        $btnTest.Text = 'Testing...'
        [System.Windows.Forms.Application]::DoEvents()
        
        try {
            $result = Test-SshConnection -RemoteHost $testHost -SshPort $testSshPort -Username $testUser `
                -Password $testPassword -IdentityFile $testKeyFile -AuthMethod $testAuthMethod -TimeoutSeconds $testTimeout
            
            if ($result.Success) {
                [System.Windows.Forms.MessageBox]::Show("Connection successful!", 'Test Connection', 'OK', 'Information') | Out-Null
            } else {
                [System.Windows.Forms.MessageBox]::Show("Connection failed:`n$($result.Message)", 'Test Connection', 'OK', 'Warning') | Out-Null
            }
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Test error: $_", 'Test Connection', 'OK', 'Error') | Out-Null
        } finally {
            $btnTest.Enabled = $true
            $btnTest.Text = 'Test Connection'
        }
    })
    $dlg.Controls.Add($btnTest)
    
    $btnOK = New-Object System.Windows.Forms.Button
    $btnOK.Text = 'Save'
    $btnOK.Location = New-Object System.Drawing.Point(300, $y)
    $btnOK.Size = New-Object System.Drawing.Size(80, 28)
    $btnOK.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $dlg.AcceptButton = $btnOK
    $dlg.Controls.Add($btnOK)
    
    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = 'Cancel'
    $btnCancel.Location = New-Object System.Drawing.Point(385, $y)
    $btnCancel.Size = New-Object System.Drawing.Size(80, 28)
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $dlg.CancelButton = $btnCancel
    $dlg.Controls.Add($btnCancel)
    
    $result = $dlg.ShowDialog()
    
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        # Parse ports safely
        $remotePort = 0
        $localPort = 0
        $sshPort = 22
        [int]::TryParse($txtRemotePort.Text.Trim(), [ref]$remotePort) | Out-Null
        [int]::TryParse($txtLocalPort.Text.Trim(), [ref]$localPort) | Out-Null
        [int]::TryParse($txtSshPort.Text.Trim(), [ref]$sshPort) | Out-Null
        if ($sshPort -eq 0) { $sshPort = 22 }
        
        return @{
            Name           = $txtName.Text.Trim()
            RemoteHost     = $txtHost.Text.Trim()
            RemotePort     = $remotePort
            LocalPort      = $localPort
            SshPort        = $sshPort
            Username       = $txtUser.Text.Trim()
            Password       = $txtPass.Text
            AuthMethod     = if ($radKey.Checked) { 'key' } else { 'password' }
            IdentityFile   = $txtKeyFile.Text.Trim()
            Group          = $cboGroup.Text.Trim()
            ConnectTimeout = [int]$numTimeout.Value
        }
    }
    return $null
}

# ---------------------------------------------------------------------------
# Log Viewer Dialog
# ---------------------------------------------------------------------------

function Show-LogViewer {
    param([string]$TunnelName)
    
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = "Log Viewer - $TunnelName"
    $dlg.Size = New-Object System.Drawing.Size(700, 500)
    $dlg.StartPosition = 'CenterParent'
    $dlg.MinimumSize = New-Object System.Drawing.Size(500, 300)
    
    $txtLog = New-Object System.Windows.Forms.TextBox
    $txtLog.Multiline = $true
    $txtLog.ScrollBars = 'Both'
    $txtLog.Font = New-Object System.Drawing.Font('Consolas', 9)
    $txtLog.ReadOnly = $true
    $txtLog.WordWrap = $false
    $txtLog.Dock = 'Fill'
    $dlg.Controls.Add($txtLog)
    
    # Button panel
    $pnlButtons = New-Object System.Windows.Forms.Panel
    $pnlButtons.Height = 40
    $pnlButtons.Dock = 'Bottom'
    $dlg.Controls.Add($pnlButtons)
    
    $btnRefresh = New-Object System.Windows.Forms.Button
    $btnRefresh.Text = 'Refresh'
    $btnRefresh.Location = New-Object System.Drawing.Point(10, 7)
    $btnRefresh.Size = New-Object System.Drawing.Size(80, 26)
    $pnlButtons.Controls.Add($btnRefresh)
    
    $btnClear = New-Object System.Windows.Forms.Button
    $btnClear.Text = 'Clear Log'
    $btnClear.Location = New-Object System.Drawing.Point(95, 7)
    $btnClear.Size = New-Object System.Drawing.Size(80, 26)
    $pnlButtons.Controls.Add($btnClear)
    
    $btnOpenFolder = New-Object System.Windows.Forms.Button
    $btnOpenFolder.Text = 'Open Folder'
    $btnOpenFolder.Location = New-Object System.Drawing.Point(180, 7)
    $btnOpenFolder.Size = New-Object System.Drawing.Size(90, 26)
    $pnlButtons.Controls.Add($btnOpenFolder)
    
    $btnClose = New-Object System.Windows.Forms.Button
    $btnClose.Text = 'Close'
    $btnClose.Location = New-Object System.Drawing.Point(590, 7)
    $btnClose.Size = New-Object System.Drawing.Size(80, 26)
    $btnClose.Anchor = 'Right,Bottom'
    $btnClose.DialogResult = 'Cancel'
    $pnlButtons.Controls.Add($btnClose)
    
    $loadLog = {
        $logPath = Get-TunnelLogPath -TunnelName $TunnelName
        if (Test-Path -LiteralPath $logPath) {
            $lines = Get-Content -LiteralPath $logPath -Tail 500
            $txtLog.Text = ($lines -join "`r`n")
            $txtLog.SelectionStart = $txtLog.Text.Length
            $txtLog.ScrollToCaret()
        } else {
            $txtLog.Text = "(No log file found at: $logPath)"
        }
    }
    
    $btnRefresh.Add_Click($loadLog)
    $btnClear.Add_Click({
        $confirm = [System.Windows.Forms.MessageBox]::Show("Clear log for '$TunnelName'?", 'Confirm', 'YesNo', 'Question')
        if ($confirm -eq 'Yes') {
            Clear-TunnelLog -TunnelName $TunnelName
            & $loadLog
        }
    })
    $btnOpenFolder.Add_Click({
        $logPath = Get-TunnelLogPath -TunnelName $TunnelName
        $folder = Split-Path -Parent $logPath
        if (Test-Path $folder) {
            Start-Process explorer.exe -ArgumentList "/select,`"$logPath`""
        }
    })
    
    # Load on open
    $dlg.Add_Load($loadLog)
    
    $dlg.ShowDialog() | Out-Null
}

# ---------------------------------------------------------------------------
# Import Dialog
# ---------------------------------------------------------------------------

function Import-TunnelsUI {
    $ofd = New-Object System.Windows.Forms.OpenFileDialog
    $ofd.Filter = 'JSON files (*.json)|*.json|All files (*.*)|*.*'
    $ofd.Title = 'Import Tunnels'
    
    if ($ofd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        # Ask how to handle duplicates
        $msg = "How should existing tunnels with the same name be handled?"
        $dlg = New-Object System.Windows.Forms.Form
        $dlg.Text = 'Import Options'
        $dlg.Size = New-Object System.Drawing.Size(350, 180)
        $dlg.StartPosition = 'CenterParent'
        $dlg.FormBorderStyle = 'FixedDialog'
        $dlg.MaximizeBox = $false
        $dlg.MinimizeBox = $false
        
        $lbl = New-Object System.Windows.Forms.Label
        $lbl.Text = $msg
        $lbl.Location = New-Object System.Drawing.Point(15, 15)
        $lbl.Size = New-Object System.Drawing.Size(310, 40)
        $dlg.Controls.Add($lbl)
        
        $radSkip = New-Object System.Windows.Forms.RadioButton
        $radSkip.Text = 'Skip existing (keep current)'
        $radSkip.Location = New-Object System.Drawing.Point(20, 55)
        $radSkip.Size = New-Object System.Drawing.Size(200, 20)
        $radSkip.Checked = $true
        $dlg.Controls.Add($radSkip)
        
        $radReplace = New-Object System.Windows.Forms.RadioButton
        $radReplace.Text = 'Replace existing'
        $radReplace.Location = New-Object System.Drawing.Point(20, 78)
        $radReplace.Size = New-Object System.Drawing.Size(200, 20)
        $dlg.Controls.Add($radReplace)
        
        $btnImport = New-Object System.Windows.Forms.Button
        $btnImport.Text = 'Import'
        $btnImport.Location = New-Object System.Drawing.Point(150, 110)
        $btnImport.Size = New-Object System.Drawing.Size(80, 28)
        $btnImport.DialogResult = 'OK'
        $dlg.AcceptButton = $btnImport
        $dlg.Controls.Add($btnImport)
        
        $btnCancel = New-Object System.Windows.Forms.Button
        $btnCancel.Text = 'Cancel'
        $btnCancel.Location = New-Object System.Drawing.Point(240, 110)
        $btnCancel.Size = New-Object System.Drawing.Size(80, 28)
        $btnCancel.DialogResult = 'Cancel'
        $dlg.CancelButton = $btnCancel
        $dlg.Controls.Add($btnCancel)
        
        if ($dlg.ShowDialog() -eq 'OK') {
            try {
                $params = @{ FilePath = $ofd.FileName }
                if ($radSkip.Checked) { $params['SkipExisting'] = $true }
                if ($radReplace.Checked) { $params['ReplaceExisting'] = $true }
                
                $result = Import-Tunnels @params
                
                $msg = "Import complete:`n"
                $msg += "- Imported: $($result.Imported)`n"
                $msg += "- Skipped: $($result.Skipped)`n"
                $msg += "- Replaced: $($result.Replaced)"
                if ($result.Errors.Count -gt 0) {
                    $msg += "`n`nErrors:`n" + ($result.Errors | Select-Object -First 5 | ForEach-Object { "- $_" }) -join "`n"
                    if ($result.Errors.Count -gt 5) { $msg += "`n... and $($result.Errors.Count - 5) more" }
                }
                if ($result.Imported -gt 0) {
                    $msg += "`n`nNote: Passwords were not imported. Please edit imported tunnels to set passwords."
                }
                
                [System.Windows.Forms.MessageBox]::Show($msg, 'Import Complete', 'OK', 'Information') | Out-Null
                return $true
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Import failed: $_", 'sshx', 'OK', 'Error') | Out-Null
            }
        }
    }
    return $false
}

# ---------------------------------------------------------------------------
# Export Dialog (Enhanced)
# ---------------------------------------------------------------------------

function Export-TunnelsUI {
    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter = 'JSON files (*.json)|*.json|All files (*.*)|*.*'
    $sfd.DefaultExt = 'json'
    $sfd.FileName = 'sshx-tunnels-export.json'
    $sfd.Title = 'Export Tunnels'
    
    if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            $count = Export-TunnelsToFile -FilePath $sfd.FileName
            [System.Windows.Forms.MessageBox]::Show("Exported $count tunnel(s) to:`n$($sfd.FileName)`n`nNote: Passwords are not exported for security.", 'Export Complete', 'OK', 'Information') | Out-Null
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Export failed: $_", 'sshx', 'OK', 'Error') | Out-Null
        }
    }
}

# ---------------------------------------------------------------------------
# Main form: tunnel list with full CRUD + new features
# ---------------------------------------------------------------------------

function Update-TunnelListView {
    param([switch]$SkipPortCheck)  # Fast refresh without port checking
    
    if ($null -eq $script:lv) { return }
    $script:lv.BeginUpdate()
    $selectedName = $null
    if ($script:lv.SelectedItems -and $script:lv.SelectedItems.Count -gt 0) { 
        $selectedName = $script:lv.SelectedItems[0].Text 
    }
    $script:lv.Items.Clear()
    try {
        $tunnels = Get-AllTunnels
        if ($null -eq $tunnels) { 
            $script:lv.EndUpdate()
            return 
        }
        foreach ($t in $tunnels) {
            if ($null -eq $t) { continue }
            
            $tunnelName = if ($t.Name) { $t.Name } else { '(unnamed)' }
            
            # Check runner process status
            $runnerAlive = $false
            if ($t.Pid) {
                $proc = Get-Process -Id $t.Pid -ErrorAction SilentlyContinue
                $runnerAlive = $null -ne $proc
            }
            
            # Get runner's own status report (more accurate than just port check)
            $runnerStatus = $null
            if ($runnerAlive) {
                $runnerStatus = Get-RunnerStatus -TunnelName $tunnelName
            }
            
            # Check if port is actually listening
            $portListening = $false
            if (-not $SkipPortCheck -and $t.LocalPort -gt 0) {
                $portListening = Test-LocalPortListening -Port ([int]$t.LocalPort)
            }
            
            # Determine display status using multiple sources of truth
            if ($portListening) {
                # Port is listening = definitely connected
                $st = 'Connected'
                $color = [System.Drawing.Color]::DarkGreen
            } elseif ($SkipPortCheck -and $runnerAlive) {
                # Just started, waiting for connection
                $st = 'Starting...'
                $color = [System.Drawing.Color]::DarkOrange
            } elseif ($runnerAlive -and $runnerStatus) {
                # Use runner's own status report
                switch ($runnerStatus.Status) {
                    'Connected' { 
                        # Runner says connected but port check failed - might be brief hiccup
                        $st = 'Connected'
                        $color = [System.Drawing.Color]::DarkGreen
                    }
                    'Connecting' { 
                        $st = 'Connecting...'
                        $color = [System.Drawing.Color]::DarkOrange
                    }
                    'Reconnecting' { 
                        $st = 'Reconnecting'
                        $color = [System.Drawing.Color]::DarkOrange
                    }
                    'Failing' {
                        $failCount = if ($runnerStatus.Failures) { $runnerStatus.Failures } else { 0 }
                        $st = if ($failCount -gt 3) { "Failing ($failCount)" } else { 'Connecting...' }
                        $color = if ($failCount -gt 3) { [System.Drawing.Color]::OrangeRed } else { [System.Drawing.Color]::DarkOrange }
                    }
                    default {
                        $st = 'Connecting...'
                        $color = [System.Drawing.Color]::DarkOrange
                    }
                }
            } elseif ($runnerAlive) {
                # Runner alive but no status file yet - probably just starting
                $st = 'Starting...'
                $color = [System.Drawing.Color]::DarkOrange
            } else {
                $st = 'Stopped'
                $color = [System.Drawing.Color]::Black
            }
            
            $groupName = if ($t.Group) { $t.Group } else { '' }
            $local = if ($t.LocalPort) { [string]$t.LocalPort } else { '' }
            $remote = "$($t.RemoteHost):$($t.RemotePort)"
            $authIcon = if ($t.AuthMethod -eq 'key') { 'Key' } else { 'Pwd' }
            $userName = if ($t.Username) { $t.Username } else { '' }
            
            $li = New-Object System.Windows.Forms.ListViewItem($tunnelName)
            $li.SubItems.Add($st) | Out-Null
            $li.SubItems.Add($groupName) | Out-Null
            $li.SubItems.Add($local) | Out-Null
            $li.SubItems.Add($remote) | Out-Null
            $li.SubItems.Add($authIcon) | Out-Null
            $li.SubItems.Add($userName) | Out-Null
            $li.Tag = $t
            $li.ForeColor = $color
            [void]$script:lv.Items.Add($li)
            if ($tunnelName -eq $selectedName) { $li.Selected = $true }
        }
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Refresh error: $_", 'sshx', 'OK', 'Warning') | Out-Null
    }
    $script:lv.EndUpdate()
}

# Update status for a single tunnel by name (faster than full refresh)
function Update-SingleTunnelStatus {
    param([string]$TunnelName, [string]$Status, [System.Drawing.Color]$Color)
    
    if ($null -eq $script:lv) { return }
    foreach ($item in $script:lv.Items) {
        if ($item.Text -eq $TunnelName) {
            $item.SubItems[1].Text = $Status
            $item.ForeColor = $Color
            break
        }
    }
}

# Schedule a delayed status check for a specific tunnel
function Schedule-StatusCheck {
    param([string]$TunnelName, [int]$DelayMs = 3000)
    
    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = $DelayMs
    $tn = $TunnelName
    $lv = $script:lv
    
    $timer.Add_Tick({
        $timer.Stop()
        $timer.Dispose()
        
        try {
            # Get tunnel info from module (module functions are accessible)
            $t = Get-TunnelByName -Name $tn
            if ($null -eq $t) { return }
            
            # Check if port is listening using module function
            $portListening = Test-LocalPortListening -Port ([int]$t.LocalPort)
            
            # Check if runner process is alive
            $runnerAlive = $false
            if ($t.Pid) {
                $proc = Get-Process -Id $t.Pid -ErrorAction SilentlyContinue
                $runnerAlive = $null -ne $proc
            }
            
            # Get runner's status report
            $runnerStatus = $null
            if ($runnerAlive) {
                $runnerStatus = Get-RunnerStatus -TunnelName $tn
            }
            
            # Determine status and color
            if ($portListening) {
                $st = 'Connected'
                $clr = [System.Drawing.Color]::DarkGreen
            } elseif ($runnerAlive -and $runnerStatus) {
                # Use runner's own status
                switch ($runnerStatus.Status) {
                    'Connected' { $st = 'Connected'; $clr = [System.Drawing.Color]::DarkGreen }
                    'Connecting' { $st = 'Connecting...'; $clr = [System.Drawing.Color]::DarkOrange }
                    'Reconnecting' { $st = 'Reconnecting'; $clr = [System.Drawing.Color]::DarkOrange }
                    'Failing' {
                        $failCount = if ($runnerStatus.Failures) { $runnerStatus.Failures } else { 0 }
                        $st = if ($failCount -gt 3) { "Failing ($failCount)" } else { 'Connecting...' }
                        $clr = if ($failCount -gt 3) { [System.Drawing.Color]::OrangeRed } else { [System.Drawing.Color]::DarkOrange }
                    }
                    default { $st = 'Connecting...'; $clr = [System.Drawing.Color]::DarkOrange }
                }
            } elseif ($runnerAlive) {
                $st = 'Starting...'
                $clr = [System.Drawing.Color]::DarkOrange
            } else {
                $st = 'Stopped'
                $clr = [System.Drawing.Color]::Black
            }
            
            # Update the ListView item
            if ($null -ne $lv) {
                foreach ($item in $lv.Items) {
                    if ($item.Text -eq $tn) {
                        $item.SubItems[1].Text = $st
                        $item.ForeColor = $clr
                        break
                    }
                }
            }
        } catch {
            # Silently ignore errors in timer callback
        }
    }.GetNewClosure())
    $timer.Start()
}

function Get-SelectedTunnel {
    if ($null -eq $script:lv -or $script:lv.SelectedItems.Count -eq 0) { return $null }
    return $script:lv.SelectedItems[0].Tag
}

function New-MainForm {
    $f = New-Object System.Windows.Forms.Form
    $f.Text = 'sshx — SSH Tunnel Manager'
    $f.Size = New-Object System.Drawing.Size(820, 480)
    $f.StartPosition = 'CenterScreen'
    $f.MinimumSize = New-Object System.Drawing.Size(700, 400)
    $script:mainForm = $f

    # --- Menu Strip ---
    $menuStrip = New-Object System.Windows.Forms.MenuStrip
    $f.MainMenuStrip = $menuStrip
    $f.Controls.Add($menuStrip)
    
    # File menu
    $menuFile = New-Object System.Windows.Forms.ToolStripMenuItem('&File')
    $miImport = New-Object System.Windows.Forms.ToolStripMenuItem('&Import...')
    $miImport.Add_Click({ if (Import-TunnelsUI) { Update-TunnelListView } })
    $menuFile.DropDownItems.Add($miImport) | Out-Null
    
    $miExport = New-Object System.Windows.Forms.ToolStripMenuItem('&Export...')
    $miExport.Add_Click({ Export-TunnelsUI })
    $menuFile.DropDownItems.Add($miExport) | Out-Null
    
    $menuFile.DropDownItems.Add((New-Object System.Windows.Forms.ToolStripSeparator)) | Out-Null
    
    $miExit = New-Object System.Windows.Forms.ToolStripMenuItem('E&xit')
    $miExit.Add_Click({ $f.Close() })
    $menuFile.DropDownItems.Add($miExit) | Out-Null
    $menuStrip.Items.Add($menuFile) | Out-Null
    
    # Tools menu
    $menuTools = New-Object System.Windows.Forms.ToolStripMenuItem('&Tools')
    
    $miAutoStart = New-Object System.Windows.Forms.ToolStripMenuItem('Run at Windows &Startup')
    $miAutoStart.CheckOnClick = $true
    $miAutoStart.Checked = Test-AutoStartEnabled
    $miAutoStart.Add_Click({
        try {
            if ($miAutoStart.Checked) {
                # Find the launcher (sshx.vbs in parent directory)
                $launcherPath = Join-Path (Split-Path -Parent $ScriptDir) 'sshx.vbs'
                if (-not (Test-Path $launcherPath)) {
                    [System.Windows.Forms.MessageBox]::Show("Launcher not found: $launcherPath", 'sshx', 'OK', 'Warning') | Out-Null
                    $miAutoStart.Checked = $false
                    return
                }
                Enable-AutoStart -LauncherPath $launcherPath
                [System.Windows.Forms.MessageBox]::Show("sshx will now start automatically when you log in.", 'Auto-Start Enabled', 'OK', 'Information') | Out-Null
            } else {
                Disable-AutoStart
                [System.Windows.Forms.MessageBox]::Show("Auto-start disabled.", 'Auto-Start Disabled', 'OK', 'Information') | Out-Null
            }
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Failed: $_", 'sshx', 'OK', 'Error') | Out-Null
            $miAutoStart.Checked = Test-AutoStartEnabled
        }
    })
    $menuTools.DropDownItems.Add($miAutoStart) | Out-Null
    
    $menuStrip.Items.Add($menuTools) | Out-Null
    
    # Help menu
    $menuHelp = New-Object System.Windows.Forms.ToolStripMenuItem('&Help')
    $miGitHub = New-Object System.Windows.Forms.ToolStripMenuItem('&GitHub Repository')
    $miGitHub.Add_Click({ Start-Process 'https://github.com/yourusername/sshx' })
    $menuHelp.DropDownItems.Add($miGitHub) | Out-Null
    
    $miAbout = New-Object System.Windows.Forms.ToolStripMenuItem('&About')
    $miAbout.Add_Click({
        [System.Windows.Forms.MessageBox]::Show("sshx - SSH Tunnel Manager`n`nVersion 2.0`n`nFeatures:`n- Password & SSH key authentication`n- Tunnel groups`n- Auto-reconnect on network changes`n- Export/Import configurations", 'About sshx', 'OK', 'Information') | Out-Null
    })
    $menuHelp.DropDownItems.Add($miAbout) | Out-Null
    $menuStrip.Items.Add($menuHelp) | Out-Null

    # --- ListView ---
    $script:lv = New-Object System.Windows.Forms.ListView
    $script:lv.View = 'Details'
    $script:lv.FullRowSelect = $true
    $script:lv.GridLines = $true
    $script:lv.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $script:lv.Location = New-Object System.Drawing.Point(12, 30)
    $script:lv.Size = New-Object System.Drawing.Size(780, 360)
    $script:lv.Columns.Add('Name', 130) | Out-Null
    $script:lv.Columns.Add('Status', 70) | Out-Null
    $script:lv.Columns.Add('Group', 80) | Out-Null
    $script:lv.Columns.Add('Local', 55) | Out-Null
    $script:lv.Columns.Add('Remote', 160) | Out-Null
    $script:lv.Columns.Add('Auth', 40) | Out-Null
    $script:lv.Columns.Add('User', 100) | Out-Null
    $f.Controls.Add($script:lv)

    $btnY = [int]$f.ClientSize.Height - 40

    # --- Toolbar Buttons ---
    # CRUD Buttons
    $btnAdd = New-Object System.Windows.Forms.Button
    $btnAdd.Text = 'Add'
    $btnAdd.Location = New-Object System.Drawing.Point(12, $btnY)
    $btnAdd.Size = New-Object System.Drawing.Size(55, 28)
    $btnAdd.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
    $f.Controls.Add($btnAdd)

    $btnEdit = New-Object System.Windows.Forms.Button
    $btnEdit.Text = 'Edit'
    $btnEdit.Location = New-Object System.Drawing.Point(72, $btnY)
    $btnEdit.Size = New-Object System.Drawing.Size(55, 28)
    $btnEdit.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
    $f.Controls.Add($btnEdit)

    $btnDuplicate = New-Object System.Windows.Forms.Button
    $btnDuplicate.Text = 'Clone'
    $btnDuplicate.Location = New-Object System.Drawing.Point(132, $btnY)
    $btnDuplicate.Size = New-Object System.Drawing.Size(55, 28)
    $btnDuplicate.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
    $f.Controls.Add($btnDuplicate)

    $btnDelete = New-Object System.Windows.Forms.Button
    $btnDelete.Text = 'Delete'
    $btnDelete.Location = New-Object System.Drawing.Point(192, $btnY)
    $btnDelete.Size = New-Object System.Drawing.Size(55, 28)
    $btnDelete.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
    $f.Controls.Add($btnDelete)

    # Separator
    $sep1 = New-Object System.Windows.Forms.Label
    $sep1.Text = '|'
    $sep1.Location = New-Object System.Drawing.Point(253, ($btnY + 5))
    $sep1.Size = New-Object System.Drawing.Size(10, 20)
    $sep1.ForeColor = [System.Drawing.Color]::LightGray
    $sep1.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
    $f.Controls.Add($sep1)

    # Action Buttons
    $btnStart = New-Object System.Windows.Forms.Button
    $btnStart.Text = 'Start'
    $btnStart.Location = New-Object System.Drawing.Point(268, $btnY)
    $btnStart.Size = New-Object System.Drawing.Size(55, 28)
    $btnStart.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
    $f.Controls.Add($btnStart)

    $btnRestart = New-Object System.Windows.Forms.Button
    $btnRestart.Text = 'Restart'
    $btnRestart.Location = New-Object System.Drawing.Point(328, $btnY)
    $btnRestart.Size = New-Object System.Drawing.Size(60, 28)
    $btnRestart.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
    $f.Controls.Add($btnRestart)

    $btnStop = New-Object System.Windows.Forms.Button
    $btnStop.Text = 'Stop'
    $btnStop.Location = New-Object System.Drawing.Point(393, $btnY)
    $btnStop.Size = New-Object System.Drawing.Size(55, 28)
    $btnStop.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
    $f.Controls.Add($btnStop)

    # Separator
    $sep2 = New-Object System.Windows.Forms.Label
    $sep2.Text = '|'
    $sep2.Location = New-Object System.Drawing.Point(454, ($btnY + 5))
    $sep2.Size = New-Object System.Drawing.Size(10, 20)
    $sep2.ForeColor = [System.Drawing.Color]::LightGray
    $sep2.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
    $f.Controls.Add($sep2)

    # Log button
    $btnLog = New-Object System.Windows.Forms.Button
    $btnLog.Text = 'Log'
    $btnLog.Location = New-Object System.Drawing.Point(469, $btnY)
    $btnLog.Size = New-Object System.Drawing.Size(50, 28)
    $btnLog.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
    $f.Controls.Add($btnLog)

    # Right side buttons
    $btnRefresh = New-Object System.Windows.Forms.Button
    $btnRefresh.Text = 'Refresh'
    $btnRefresh.Location = New-Object System.Drawing.Point(([int]$f.ClientSize.Width - 85), $btnY)
    $btnRefresh.Size = New-Object System.Drawing.Size(70, 28)
    $btnRefresh.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
    $f.Controls.Add($btnRefresh)

    # --- Context menu ---
    $ctx = New-Object System.Windows.Forms.ContextMenuStrip
    $miStart = $ctx.Items.Add('Start')
    $miRestart = $ctx.Items.Add('Restart')
    $miStop = $ctx.Items.Add('Stop')
    $ctx.Items.Add('-') | Out-Null
    $miCtxEdit = $ctx.Items.Add('Edit...')
    $miCtxDuplicate = $ctx.Items.Add('Clone')
    $miCtxDelete = $ctx.Items.Add('Delete')
    $ctx.Items.Add('-') | Out-Null
    $miCtxLog = $ctx.Items.Add('View Log...')
    $script:lv.ContextMenuStrip = $ctx

    # --- Action handlers ---
    $script:act = {
        $t = Get-SelectedTunnel
        if (-not $t) {
            [System.Windows.Forms.MessageBox]::Show('Select a tunnel first.', 'sshx', 'OK', 'Information') | Out-Null
            return
        }
        $n = $t.Name
        $actName = $args[0]
        Write-SSHXLog "Action: $actName tunnel '$n'"
        
        # Show immediate visual feedback
        if ($actName -eq 'Start' -or $actName -eq 'Restart') {
            Update-SingleTunnelStatus -TunnelName $n -Status 'Starting...' -Color ([System.Drawing.Color]::DarkOrange)
        } elseif ($actName -eq 'Stop') {
            Update-SingleTunnelStatus -TunnelName $n -Status 'Stopping...' -Color ([System.Drawing.Color]::Gray)
        }
        [System.Windows.Forms.Application]::DoEvents()
        
        try {
            if ($actName -eq 'Start')   { Start-Tunnel -Name $n | Out-Null }
            if ($actName -eq 'Restart') { 
                Stop-Tunnel -Name $n -ErrorAction SilentlyContinue | Out-Null
                Start-Sleep -Milliseconds 400
                Start-Tunnel -Name $n | Out-Null 
            }
            if ($actName -eq 'Stop') { 
                Stop-Tunnel -Name $n | Out-Null 
            }
            Write-SSHXLog "Action: $actName completed for '$n'"
            
            if ($actName -eq 'Start' -or $actName -eq 'Restart') {
                Schedule-StatusCheck -TunnelName $n -DelayMs 2500
            } else {
                Update-SingleTunnelStatus -TunnelName $n -Status 'Stopped' -Color ([System.Drawing.Color]::Black)
            }
        } catch {
            Write-SSHXLog "Action: $actName failed for '$n': $_" -Level 'ERROR'
            [System.Windows.Forms.MessageBox]::Show("$actName failed: $_", 'sshx', 'OK', 'Warning') | Out-Null
            Update-TunnelListView
        }
    }

    # Add tunnel
    $script:addTunnel = {
        Write-SSHXLog "Action: Adding new tunnel"
        $data = Show-TunnelDialog -Title 'Add Tunnel'
        if ($null -eq $data) { return }
        
        # Validation
        $errors = @()
        if ([string]::IsNullOrWhiteSpace($data.Name)) { $errors += 'Name is required' }
        if ([string]::IsNullOrWhiteSpace($data.RemoteHost)) { $errors += 'Remote Host is required' }
        if ($data.RemotePort -le 0 -or $data.RemotePort -gt 65535) { $errors += 'Remote Port must be between 1 and 65535' }
        if ($data.LocalPort -le 0 -or $data.LocalPort -gt 65535) { $errors += 'Local Port must be between 1 and 65535' }
        if ($data.SshPort -le 0 -or $data.SshPort -gt 65535) { $errors += 'SSH Port must be between 1 and 65535' }
        if ([string]::IsNullOrWhiteSpace($data.Username)) { $errors += 'Username is required' }
        
        if ($data.AuthMethod -eq 'password') {
            if ([string]::IsNullOrWhiteSpace($data.Password)) { $errors += 'Password is required for password authentication' }
        } else {
            if ([string]::IsNullOrWhiteSpace($data.IdentityFile)) { $errors += 'SSH Key file is required for key authentication' }
            elseif (-not (Test-Path -LiteralPath $data.IdentityFile)) { $errors += "SSH Key file not found: $($data.IdentityFile)" }
        }
        
        if (-not [string]::IsNullOrWhiteSpace($data.Name)) {
            $existing = Get-TunnelByName -Name $data.Name
            if ($existing) { $errors += "Tunnel named '$($data.Name)' already exists" }
        }
        
        if ($data.LocalPort -gt 0) {
            try { Test-LocalPortAvailable -LocalPort $data.LocalPort | Out-Null }
            catch { $errors += $_.Exception.Message }
        }
        
        if ($errors.Count -gt 0) {
            [System.Windows.Forms.MessageBox]::Show(($errors -join "`n"), 'Validation Error', 'OK', 'Warning') | Out-Null
            return
        }
        
        try {
            $params = @{
                Name = $data.Name
                RemoteHost = $data.RemoteHost
                RemotePort = $data.RemotePort
                LocalPort = $data.LocalPort
                Username = $data.Username
                SshPort = $data.SshPort
                AuthMethod = $data.AuthMethod
                Group = $data.Group
                ConnectTimeout = $data.ConnectTimeout
            }
            if ($data.AuthMethod -eq 'password') {
                $params['PasswordPlain'] = $data.Password
            } else {
                $params['IdentityFile'] = $data.IdentityFile
            }
            
            Add-Tunnel @params | Out-Null
            Update-TunnelListView
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Add failed: $_", 'sshx', 'OK', 'Error') | Out-Null
        }
    }

    # Edit tunnel
    $script:editTunnel = {
        $t = Get-SelectedTunnel
        if (-not $t) {
            [System.Windows.Forms.MessageBox]::Show('Select a tunnel first.', 'sshx', 'OK', 'Information') | Out-Null
            return
        }
        $data = Show-TunnelDialog -Title 'Edit Tunnel' -Tunnel $t
        if ($null -eq $data) { return }
        
        Write-SSHXLog "Action: Editing tunnel '$($t.Name)'"
        
        # Validation
        $errors = @()
        if ([string]::IsNullOrWhiteSpace($data.Name)) { $errors += 'Name is required' }
        if ([string]::IsNullOrWhiteSpace($data.RemoteHost)) { $errors += 'Remote Host is required' }
        if ($data.RemotePort -le 0 -or $data.RemotePort -gt 65535) { $errors += 'Remote Port must be between 1 and 65535' }
        if ($data.LocalPort -le 0 -or $data.LocalPort -gt 65535) { $errors += 'Local Port must be between 1 and 65535' }
        if ($data.SshPort -le 0 -or $data.SshPort -gt 65535) { $errors += 'SSH Port must be between 1 and 65535' }
        if ([string]::IsNullOrWhiteSpace($data.Username)) { $errors += 'Username is required' }
        
        if ($data.AuthMethod -eq 'key' -and [string]::IsNullOrWhiteSpace($data.IdentityFile)) {
            $errors += 'SSH Key file is required for key authentication'
        }
        
        if ($data.Name -ne $t.Name) {
            $existing = Get-TunnelByName -Name $data.Name
            if ($existing) { $errors += "Tunnel named '$($data.Name)' already exists" }
        }
        
        if ($data.LocalPort -ne [int]$t.LocalPort) {
            try { Test-LocalPortAvailable -LocalPort $data.LocalPort -ExcludeTunnelName $t.Name | Out-Null }
            catch { $errors += $_.Exception.Message }
        }
        
        if ($errors.Count -gt 0) {
            [System.Windows.Forms.MessageBox]::Show(($errors -join "`n"), 'Validation Error', 'OK', 'Warning') | Out-Null
            return
        }
        
        try {
            $params = @{ Name = $t.Name }
            if ($data.Name -ne $t.Name) { $params['NewName'] = $data.Name }
            if ($data.RemoteHost) { $params['RemoteHost'] = $data.RemoteHost }
            if ($data.RemotePort -gt 0) { $params['RemotePort'] = $data.RemotePort }
            if ($data.LocalPort -gt 0) { $params['LocalPort'] = $data.LocalPort }
            if ($data.SshPort -gt 0) { $params['SshPort'] = $data.SshPort }
            if ($data.Username) { $params['Username'] = $data.Username }
            $params['AuthMethod'] = $data.AuthMethod
            $params['Group'] = $data.Group
            $params['ConnectTimeout'] = $data.ConnectTimeout
            
            if ($data.AuthMethod -eq 'password' -and -not [string]::IsNullOrWhiteSpace($data.Password)) {
                $params['PasswordPlain'] = $data.Password
            }
            if ($data.AuthMethod -eq 'key') {
                $params['IdentityFile'] = $data.IdentityFile
            }
            
            Update-Tunnel @params | Out-Null
            Write-SSHXLog "Action: Tunnel updated"
            Update-TunnelListView
        } catch {
            Write-SSHXLog "Action: Edit failed - $_" -Level 'ERROR'
            [System.Windows.Forms.MessageBox]::Show("Edit failed: $_", 'sshx', 'OK', 'Error') | Out-Null
        }
    }

    # Duplicate tunnel
    $script:duplicateTunnel = {
        $t = Get-SelectedTunnel
        if (-not $t) {
            [System.Windows.Forms.MessageBox]::Show('Select a tunnel first.', 'sshx', 'OK', 'Information') | Out-Null
            return
        }
        Write-SSHXLog "Action: Duplicating tunnel '$($t.Name)'"
        try {
            $newTunnel = Copy-Tunnel -SourceName $t.Name
            [System.Windows.Forms.MessageBox]::Show("Created '$($newTunnel.Name)' as copy of '$($t.Name)'", 'Tunnel Cloned', 'OK', 'Information') | Out-Null
            Update-TunnelListView
        } catch {
            Write-SSHXLog "Action: Duplicate failed - $_" -Level 'ERROR'
            [System.Windows.Forms.MessageBox]::Show("Clone failed: $_", 'sshx', 'OK', 'Error') | Out-Null
        }
    }

    # Delete tunnel
    $script:deleteTunnel = {
        $t = Get-SelectedTunnel
        if (-not $t) {
            [System.Windows.Forms.MessageBox]::Show('Select a tunnel first.', 'sshx', 'OK', 'Information') | Out-Null
            return
        }
        $confirm = [System.Windows.Forms.MessageBox]::Show("Delete tunnel '$($t.Name)'?`n`nThis will stop the tunnel if running.", 'Confirm Delete', 'YesNo', 'Question')
        if ($confirm -eq [System.Windows.Forms.DialogResult]::Yes) {
            Write-SSHXLog "Action: Deleting tunnel '$($t.Name)'"
            try {
                Remove-Tunnel -Name $t.Name
                Write-SSHXLog "Action: Tunnel deleted"
                Update-TunnelListView
            } catch {
                Write-SSHXLog "Action: Delete failed - $_" -Level 'ERROR'
                [System.Windows.Forms.MessageBox]::Show("Delete failed: $_", 'sshx', 'OK', 'Error') | Out-Null
            }
        }
    }

    # View log
    $script:viewLog = {
        $t = Get-SelectedTunnel
        if (-not $t) {
            [System.Windows.Forms.MessageBox]::Show('Select a tunnel first.', 'sshx', 'OK', 'Information') | Out-Null
            return
        }
        Show-LogViewer -TunnelName $t.Name
    }

    # --- Wire up buttons ---
    $btnAdd.Add_Click($script:addTunnel)
    $btnEdit.Add_Click($script:editTunnel)
    $btnDuplicate.Add_Click($script:duplicateTunnel)
    $btnDelete.Add_Click($script:deleteTunnel)
    $btnStart.Add_Click({ & $script:act 'Start' })
    $btnRestart.Add_Click({ & $script:act 'Restart' })
    $btnStop.Add_Click({ & $script:act 'Stop' })
    $btnLog.Add_Click($script:viewLog)
    $btnRefresh.Add_Click({ Update-TunnelListView })
    
    # F5 to refresh
    $f.KeyPreview = $true
    $f.Add_KeyDown({
        param($sender, $e)
        if ($e.KeyCode -eq [System.Windows.Forms.Keys]::F5) {
            Update-TunnelListView
            $e.Handled = $true
        }
    })

    # Context menu
    $miStart.Add_Click({ & $script:act 'Start' })
    $miRestart.Add_Click({ & $script:act 'Restart' })
    $miStop.Add_Click({ & $script:act 'Stop' })
    $miCtxEdit.Add_Click($script:editTunnel)
    $miCtxDuplicate.Add_Click($script:duplicateTunnel)
    $miCtxDelete.Add_Click($script:deleteTunnel)
    $miCtxLog.Add_Click($script:viewLog)

    # Double-click to edit
    $script:lv.Add_DoubleClick($script:editTunnel)

    # Load tunnels when form opens
    $f.Add_Load({ 
        Write-SSHXLog "UI: Form loaded"
        Update-TunnelListView
    })

    # Cleanup on close
    $f.Add_FormClosing({
        param($sender, $e)
        Write-SSHXLog "UI: Closing"
    })

    return $f
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

try {
    Get-SshPath | Out-Null
} catch {
    [System.Windows.Forms.MessageBox]::Show("$_`n`nWindows OpenSSH client is required.`nGo to: Settings > Apps > Optional Features > Add OpenSSH Client", 'sshx', 'OK', 'Error') | Out-Null
    exit 1
}

New-IntroForm | Out-Null
$main = New-MainForm
[System.Windows.Forms.Application]::Run($main)
