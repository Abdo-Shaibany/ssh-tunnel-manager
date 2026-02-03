<#
.SYNOPSIS
  sshx — SSH Tunnel Manager with full CRUD operations.
  UI: binary "sshx" banner with 3D-style rotation, tunnel list, Add/Edit/Delete, Start/Restart/Stop, Export.
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

# ---------------------------------------------------------------------------
# Intro: Simple "sshx" title with subtitle
# ---------------------------------------------------------------------------

$introDurationMs = 2500

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
# Add/Edit Tunnel Dialog
# ---------------------------------------------------------------------------

function Show-TunnelDialog {
    param(
        [string]$Title = 'Add Tunnel',
        [object]$Tunnel = $null  # null for Add, existing tunnel for Edit
    )
    
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = $Title
    $dlg.Size = New-Object System.Drawing.Size(400, 320)
    $dlg.StartPosition = 'CenterParent'
    $dlg.FormBorderStyle = 'FixedDialog'
    $dlg.MaximizeBox = $false
    $dlg.MinimizeBox = $false
    
    $y = 15
    $lblWidth = 100
    $txtWidth = 250
    
    # Name
    $lblName = New-Object System.Windows.Forms.Label
    $lblName.Text = 'Name:'
    $lblName.Location = New-Object System.Drawing.Point(15, $y)
    $lblName.Size = New-Object System.Drawing.Size($lblWidth, 20)
    $dlg.Controls.Add($lblName)
    
    $txtName = New-Object System.Windows.Forms.TextBox
    $txtName.Location = New-Object System.Drawing.Point(120, $y)
    $txtName.Size = New-Object System.Drawing.Size($txtWidth, 20)
    if ($Tunnel) { $txtName.Text = $Tunnel.Name }
    $dlg.Controls.Add($txtName)
    $y += 30
    
    # Remote Host
    $lblHost = New-Object System.Windows.Forms.Label
    $lblHost.Text = 'Remote Host:'
    $lblHost.Location = New-Object System.Drawing.Point(15, $y)
    $lblHost.Size = New-Object System.Drawing.Size($lblWidth, 20)
    $dlg.Controls.Add($lblHost)
    
    $txtHost = New-Object System.Windows.Forms.TextBox
    $txtHost.Location = New-Object System.Drawing.Point(120, $y)
    $txtHost.Size = New-Object System.Drawing.Size($txtWidth, 20)
    if ($Tunnel) { $txtHost.Text = $Tunnel.RemoteHost }
    $dlg.Controls.Add($txtHost)
    $y += 30
    
    # Remote Port
    $lblRemotePort = New-Object System.Windows.Forms.Label
    $lblRemotePort.Text = 'Remote Port:'
    $lblRemotePort.Location = New-Object System.Drawing.Point(15, $y)
    $lblRemotePort.Size = New-Object System.Drawing.Size($lblWidth, 20)
    $dlg.Controls.Add($lblRemotePort)
    
    $txtRemotePort = New-Object System.Windows.Forms.TextBox
    $txtRemotePort.Location = New-Object System.Drawing.Point(120, $y)
    $txtRemotePort.Size = New-Object System.Drawing.Size(80, 20)
    if ($Tunnel) { $txtRemotePort.Text = [string]$Tunnel.RemotePort }
    $dlg.Controls.Add($txtRemotePort)
    $y += 30
    
    # Local Port
    $lblLocalPort = New-Object System.Windows.Forms.Label
    $lblLocalPort.Text = 'Local Port:'
    $lblLocalPort.Location = New-Object System.Drawing.Point(15, $y)
    $lblLocalPort.Size = New-Object System.Drawing.Size($lblWidth, 20)
    $dlg.Controls.Add($lblLocalPort)
    
    $txtLocalPort = New-Object System.Windows.Forms.TextBox
    $txtLocalPort.Location = New-Object System.Drawing.Point(120, $y)
    $txtLocalPort.Size = New-Object System.Drawing.Size(80, 20)
    if ($Tunnel) { $txtLocalPort.Text = [string]$Tunnel.LocalPort }
    $dlg.Controls.Add($txtLocalPort)
    $y += 30
    
    # SSH Port
    $lblSshPort = New-Object System.Windows.Forms.Label
    $lblSshPort.Text = 'SSH Port:'
    $lblSshPort.Location = New-Object System.Drawing.Point(15, $y)
    $lblSshPort.Size = New-Object System.Drawing.Size($lblWidth, 20)
    $dlg.Controls.Add($lblSshPort)
    
    $txtSshPort = New-Object System.Windows.Forms.TextBox
    $txtSshPort.Location = New-Object System.Drawing.Point(120, $y)
    $txtSshPort.Size = New-Object System.Drawing.Size(80, 20)
    $txtSshPort.Text = if ($Tunnel -and $Tunnel.SshPort) { [string]$Tunnel.SshPort } else { '22' }
    $dlg.Controls.Add($txtSshPort)
    $y += 30
    
    # Username
    $lblUser = New-Object System.Windows.Forms.Label
    $lblUser.Text = 'Username:'
    $lblUser.Location = New-Object System.Drawing.Point(15, $y)
    $lblUser.Size = New-Object System.Drawing.Size($lblWidth, 20)
    $dlg.Controls.Add($lblUser)
    
    $txtUser = New-Object System.Windows.Forms.TextBox
    $txtUser.Location = New-Object System.Drawing.Point(120, $y)
    $txtUser.Size = New-Object System.Drawing.Size($txtWidth, 20)
    if ($Tunnel) { $txtUser.Text = $Tunnel.Username }
    $dlg.Controls.Add($txtUser)
    $y += 30
    
    # Password
    $lblPass = New-Object System.Windows.Forms.Label
    $lblPass.Text = 'Password:'
    $lblPass.Location = New-Object System.Drawing.Point(15, $y)
    $lblPass.Size = New-Object System.Drawing.Size($lblWidth, 20)
    $dlg.Controls.Add($lblPass)
    
    $txtPass = New-Object System.Windows.Forms.TextBox
    $txtPass.Location = New-Object System.Drawing.Point(120, $y)
    $txtPass.Size = New-Object System.Drawing.Size($txtWidth, 20)
    $txtPass.UseSystemPasswordChar = $true
    # Don't pre-fill password for security
    $dlg.Controls.Add($txtPass)
    
    $lblPassHint = New-Object System.Windows.Forms.Label
    $lblPassHint.Text = if ($Tunnel) { '(leave blank to keep existing)' } else { '' }
    $hintY = $y + 22
    $lblPassHint.Location = New-Object System.Drawing.Point(120, $hintY)
    $lblPassHint.Size = New-Object System.Drawing.Size($txtWidth, 15)
    $lblPassHint.ForeColor = [System.Drawing.Color]::Gray
    $lblPassHint.Font = New-Object System.Drawing.Font('Segoe UI', 8)
    $dlg.Controls.Add($lblPassHint)
    $y += 50
    
    # Buttons
    $btnOK = New-Object System.Windows.Forms.Button
    $btnOK.Text = 'Save'
    $btnOK.Location = New-Object System.Drawing.Point(200, $y)
    $btnOK.Size = New-Object System.Drawing.Size(80, 28)
    $btnOK.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $dlg.AcceptButton = $btnOK
    $dlg.Controls.Add($btnOK)
    
    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = 'Cancel'
    $btnCancel.Location = New-Object System.Drawing.Point(290, $y)
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
            Name       = $txtName.Text.Trim()
            RemoteHost = $txtHost.Text.Trim()
            RemotePort = $remotePort
            LocalPort  = $localPort
            SshPort    = $sshPort
            Username   = $txtUser.Text.Trim()
            Password   = $txtPass.Text
        }
    }
    return $null
}

# ---------------------------------------------------------------------------
# Export Dialog
# ---------------------------------------------------------------------------

function Export-Tunnels {
    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter = 'JSON files (*.json)|*.json|All files (*.*)|*.*'
    $sfd.DefaultExt = 'json'
    $sfd.FileName = 'sshx-tunnels-export.json'
    $sfd.Title = 'Export Tunnels'
    
    if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            $tunnels = Get-AllTunnels
            $exportList = @()
            foreach ($t in $tunnels) {
                $exportList += [pscustomobject]@{
                    Name       = $t.Name
                    RemoteHost = $t.RemoteHost
                    RemotePort = $t.RemotePort
                    LocalPort  = $t.LocalPort
                    SshPort    = $t.SshPort
                    Username   = $t.Username
                    # Password is NOT exported for security - user must re-enter
                }
            }
            $exportList | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $sfd.FileName -Encoding UTF8
            [System.Windows.Forms.MessageBox]::Show("Exported $($exportList.Count) tunnel(s) to:`n$($sfd.FileName)`n`nNote: Passwords are not exported for security.", 'Export Complete', 'OK', 'Information') | Out-Null
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Export failed: $_", 'sshx', 'OK', 'Error') | Out-Null
        }
    }
}

# ---------------------------------------------------------------------------
# Main form: tunnel list with full CRUD
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
            
            # Check if port is actually listening (tunnel might be working even if we lost track of PID)
            $portListening = $false
            if (-not $SkipPortCheck -and $t.LocalPort -gt 0) {
                $portListening = Test-LocalPortListening -Port ([int]$t.LocalPort)
            }
            
            # Determine display status - port listening is the source of truth
            if ($portListening) {
                # Port is listening = tunnel is working (regardless of PID tracking)
                $st = 'Connected'
                $color = [System.Drawing.Color]::DarkGreen
            } elseif ($SkipPortCheck -and $runnerAlive) {
                # Show intermediate state during actions
                $st = 'Starting...'
                $color = [System.Drawing.Color]::DarkOrange
            } elseif ($runnerAlive) {
                # Runner is alive but port not listening = failing
                $st = 'Failing'
                $color = [System.Drawing.Color]::OrangeRed
            } else {
                $st = 'Stopped'
                $color = [System.Drawing.Color]::Black
            }
            
            $local = if ($t.LocalPort) { [string]$t.LocalPort } else { '' }
            $remote = "$($t.RemoteHost):$($t.RemotePort)"
            $ssh = if ($t.SshPort -and $t.SshPort -ne 22) { [string]$t.SshPort } else { '22' }
            $userName = if ($t.Username) { $t.Username } else { '' }
            
            $li = New-Object System.Windows.Forms.ListViewItem($tunnelName)
            $li.SubItems.Add($st) | Out-Null
            $li.SubItems.Add($local) | Out-Null
            $li.SubItems.Add($remote) | Out-Null
            $li.SubItems.Add($ssh) | Out-Null
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
    param([string]$TunnelName, [int]$DelayMs = 2500)
    
    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = $DelayMs
    $tn = $TunnelName
    $lv = $script:lv  # Capture reference to ListView
    
    $timer.Add_Tick({
        $timer.Stop()
        $timer.Dispose()
        
        # Check actual status
        $t = Get-TunnelByName -Name $tn
        if ($null -eq $t) { return }
        
        # Port listening is the source of truth
        $portListening = Test-LocalPortListening -Port ([int]$t.LocalPort)
        
        $runnerAlive = $false
        if ($t.Pid) {
            $proc = Get-Process -Id $t.Pid -ErrorAction SilentlyContinue
            $runnerAlive = $null -ne $proc
        }
        
        # Determine status and color - port listening takes priority
        if ($portListening) {
            $st = 'Connected'
            $clr = [System.Drawing.Color]::DarkGreen
        } elseif ($runnerAlive) {
            $st = 'Failing'
            $clr = [System.Drawing.Color]::OrangeRed
        } else {
            $st = 'Stopped'
            $clr = [System.Drawing.Color]::Black
        }
        
        # Update the ListView item directly (inlined to avoid scope issues)
        if ($null -ne $lv) {
            foreach ($item in $lv.Items) {
                if ($item.Text -eq $tn) {
                    $item.SubItems[1].Text = $st
                    $item.ForeColor = $clr
                    break
                }
            }
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
    $f.Size = New-Object System.Drawing.Size(750, 450)
    $f.StartPosition = 'CenterScreen'
    $f.MinimumSize = New-Object System.Drawing.Size(650, 380)

    $script:lv = New-Object System.Windows.Forms.ListView
    $script:lv.View = 'Details'
    $script:lv.FullRowSelect = $true
    $script:lv.GridLines = $true
    $script:lv.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $script:lv.Location = New-Object System.Drawing.Point(12, 12)
    $script:lv.Size = New-Object System.Drawing.Size(710, 340)
    $script:lv.Columns.Add('Name', 120) | Out-Null
    $script:lv.Columns.Add('Status', 70) | Out-Null
    $script:lv.Columns.Add('Local', 60) | Out-Null
    $script:lv.Columns.Add('Remote', 180) | Out-Null
    $script:lv.Columns.Add('SSH', 50) | Out-Null
    $script:lv.Columns.Add('User', 100) | Out-Null
    $f.Controls.Add($script:lv)

    $btnY = [int]$f.ClientSize.Height - 40

    # CRUD Buttons
    $btnAdd = New-Object System.Windows.Forms.Button
    $btnAdd.Text = 'Add'
    $btnAdd.Location = New-Object System.Drawing.Point(12, $btnY)
    $btnAdd.Size = New-Object System.Drawing.Size(60, 28)
    $btnAdd.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
    $f.Controls.Add($btnAdd)

    $btnEdit = New-Object System.Windows.Forms.Button
    $btnEdit.Text = 'Edit'
    $btnEdit.Location = New-Object System.Drawing.Point(77, $btnY)
    $btnEdit.Size = New-Object System.Drawing.Size(60, 28)
    $btnEdit.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
    $f.Controls.Add($btnEdit)

    $btnDelete = New-Object System.Windows.Forms.Button
    $btnDelete.Text = 'Delete'
    $btnDelete.Location = New-Object System.Drawing.Point(142, $btnY)
    $btnDelete.Size = New-Object System.Drawing.Size(60, 28)
    $btnDelete.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
    $f.Controls.Add($btnDelete)

    # Separator
    $sep1 = New-Object System.Windows.Forms.Label
    $sep1.Text = '|'
    $sepY = $btnY + 5
    $sep1.Location = New-Object System.Drawing.Point(210, $sepY)
    $sep1.Size = New-Object System.Drawing.Size(10, 20)
    $sep1.ForeColor = [System.Drawing.Color]::LightGray
    $sep1.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
    $f.Controls.Add($sep1)

    # Action Buttons
    $btnStart = New-Object System.Windows.Forms.Button
    $btnStart.Text = 'Start'
    $btnStart.Location = New-Object System.Drawing.Point(225, $btnY)
    $btnStart.Size = New-Object System.Drawing.Size(60, 28)
    $btnStart.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
    $f.Controls.Add($btnStart)

    $btnRestart = New-Object System.Windows.Forms.Button
    $btnRestart.Text = 'Restart'
    $btnRestart.Location = New-Object System.Drawing.Point(290, $btnY)
    $btnRestart.Size = New-Object System.Drawing.Size(65, 28)
    $btnRestart.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
    $f.Controls.Add($btnRestart)

    $btnStop = New-Object System.Windows.Forms.Button
    $btnStop.Text = 'Stop'
    $btnStop.Location = New-Object System.Drawing.Point(360, $btnY)
    $btnStop.Size = New-Object System.Drawing.Size(60, 28)
    $btnStop.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
    $f.Controls.Add($btnStop)

    # GitHub Link (center-ish)
    $lnkGitHub = New-Object System.Windows.Forms.LinkLabel
    $lnkGitHub.Text = 'GitHub'
    $lnkGitHub.Location = New-Object System.Drawing.Point(430, ($btnY + 6))
    $lnkGitHub.Size = New-Object System.Drawing.Size(45, 16)
    $lnkGitHub.LinkColor = [System.Drawing.Color]::RoyalBlue
    $lnkGitHub.ActiveLinkColor = [System.Drawing.Color]::DodgerBlue
    $lnkGitHub.VisitedLinkColor = [System.Drawing.Color]::RoyalBlue
    $lnkGitHub.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom
    $lnkGitHub.Add_LinkClicked({
        # Change this URL to your actual GitHub repo
        Start-Process 'https://github.com/yourusername/sshx'
    })
    $f.Controls.Add($lnkGitHub)

    # Refresh Button (right side)
    $btnRefresh = New-Object System.Windows.Forms.Button
    $btnRefresh.Text = 'Refresh'
    $refreshX = [int]$f.ClientSize.Width - 165
    $btnRefresh.Location = New-Object System.Drawing.Point($refreshX, $btnY)
    $btnRefresh.Size = New-Object System.Drawing.Size(70, 28)
    $btnRefresh.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
    $f.Controls.Add($btnRefresh)

    # Export Button (right side)
    $btnExport = New-Object System.Windows.Forms.Button
    $btnExport.Text = 'Export...'
    $exportX = [int]$f.ClientSize.Width - 85
    $btnExport.Location = New-Object System.Drawing.Point($exportX, $btnY)
    $btnExport.Size = New-Object System.Drawing.Size(70, 28)
    $btnExport.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
    $f.Controls.Add($btnExport)

    # Context menu
    $ctx = New-Object System.Windows.Forms.ContextMenuStrip
    $miStart = $ctx.Items.Add('Start')
    $miRestart = $ctx.Items.Add('Restart')
    $miStop = $ctx.Items.Add('Stop')
    $ctx.Items.Add('-') | Out-Null
    $miEdit = $ctx.Items.Add('Edit...')
    $miDelete = $ctx.Items.Add('Delete')
    $script:lv.ContextMenuStrip = $ctx

    # Action handler (script scope so event handlers can access it)
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
        [System.Windows.Forms.Application]::DoEvents()  # Force UI update
        
        try {
            if ($actName -eq 'Start')   { Start-Tunnel -Name $n | Out-Null }
            if ($actName -eq 'Restart') { 
                Stop-Tunnel -Name $n -ErrorAction SilentlyContinue | Out-Null
                Start-Sleep -Milliseconds 400
                Start-Tunnel -Name $n | Out-Null 
            }
            if ($actName -eq 'Stop')    { Stop-Tunnel -Name $n | Out-Null }
            Write-SSHXLog "Action: $actName completed for '$n'"
            
            # Schedule delayed status check (tunnel needs time to establish)
            if ($actName -eq 'Start' -or $actName -eq 'Restart') {
                Schedule-StatusCheck -TunnelName $n -DelayMs 2500
            } else {
                # Stop is immediate
                Update-SingleTunnelStatus -TunnelName $n -Status 'Stopped' -Color ([System.Drawing.Color]::Black)
            }
        } catch {
            Write-SSHXLog "Action: $actName failed for '$n': $_" -Level 'ERROR'
            [System.Windows.Forms.MessageBox]::Show("$actName failed: $_", 'sshx', 'OK', 'Warning') | Out-Null
            # Refresh to show actual state after error
            Update-TunnelListView
        }
    }

    # Add tunnel
    $script:addTunnel = {
        Write-SSHXLog "Action: Adding new tunnel"
        $data = Show-TunnelDialog -Title 'Add Tunnel'
        if ($null -eq $data) { return }
        
        # Basic validation (detailed validation in core module)
        $errors = @()
        if ([string]::IsNullOrWhiteSpace($data.Name)) { $errors += 'Name is required' }
        if ([string]::IsNullOrWhiteSpace($data.RemoteHost)) { $errors += 'Remote Host is required' }
        if ($data.RemotePort -le 0 -or $data.RemotePort -gt 65535) { $errors += 'Remote Port must be between 1 and 65535' }
        if ($data.LocalPort -le 0 -or $data.LocalPort -gt 65535) { $errors += 'Local Port must be between 1 and 65535' }
        if ($data.SshPort -le 0 -or $data.SshPort -gt 65535) { $errors += 'SSH Port must be between 1 and 65535' }
        if ([string]::IsNullOrWhiteSpace($data.Username)) { $errors += 'Username is required' }
        if ([string]::IsNullOrWhiteSpace($data.Password)) { $errors += 'Password is required for new tunnels' }
        
        # Check for duplicate tunnel name
        if (-not [string]::IsNullOrWhiteSpace($data.Name)) {
            $existing = Get-TunnelByName -Name $data.Name
            if ($existing) { $errors += "Tunnel named '$($data.Name)' already exists" }
        }
        
        # Check for local port conflict
        if ($data.LocalPort -gt 0) {
            try {
                Test-LocalPortAvailable -LocalPort $data.LocalPort | Out-Null
            } catch {
                $errors += $_.Exception.Message
            }
        }
        
        # Check for duplicate config
        if ($data.RemotePort -gt 0 -and $data.LocalPort -gt 0 -and -not [string]::IsNullOrWhiteSpace($data.RemoteHost)) {
            try {
                Test-DuplicateTunnel -RemoteHost $data.RemoteHost -RemotePort $data.RemotePort -LocalPort $data.LocalPort | Out-Null
            } catch {
                $errors += $_.Exception.Message
            }
        }
        
        if ($errors.Count -gt 0) {
            [System.Windows.Forms.MessageBox]::Show(($errors -join "`n"), 'Validation Error', 'OK', 'Warning') | Out-Null
            return
        }
        
        try {
            Add-Tunnel -Name $data.Name -RemoteHost $data.RemoteHost -RemotePort $data.RemotePort `
                -LocalPort $data.LocalPort -Username $data.Username -PasswordPlain $data.Password `
                -SshPort $data.SshPort | Out-Null
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
        if ($data) {
            Write-SSHXLog "Action: Editing tunnel '$($t.Name)'"
            
            # Validation
            $errors = @()
            if ([string]::IsNullOrWhiteSpace($data.Name)) { $errors += 'Name is required' }
            if ([string]::IsNullOrWhiteSpace($data.RemoteHost)) { $errors += 'Remote Host is required' }
            if ($data.RemotePort -le 0 -or $data.RemotePort -gt 65535) { $errors += 'Remote Port must be between 1 and 65535' }
            if ($data.LocalPort -le 0 -or $data.LocalPort -gt 65535) { $errors += 'Local Port must be between 1 and 65535' }
            if ($data.SshPort -le 0 -or $data.SshPort -gt 65535) { $errors += 'SSH Port must be between 1 and 65535' }
            if ([string]::IsNullOrWhiteSpace($data.Username)) { $errors += 'Username is required' }
            
            # Check for duplicate name if renaming
            if ($data.Name -ne $t.Name) {
                $existing = Get-TunnelByName -Name $data.Name
                if ($existing) { $errors += "Tunnel named '$($data.Name)' already exists" }
            }
            
            # Check for local port conflict if changing local port
            if ($data.LocalPort -ne [int]$t.LocalPort) {
                try {
                    Test-LocalPortAvailable -LocalPort $data.LocalPort -ExcludeTunnelName $t.Name | Out-Null
                } catch {
                    $errors += $_.Exception.Message
                }
            }
            
            # Check for duplicate config if changing tunnel settings
            $configChanged = ($data.RemoteHost -ne $t.RemoteHost) -or ($data.RemotePort -ne [int]$t.RemotePort) -or ($data.LocalPort -ne [int]$t.LocalPort)
            if ($configChanged) {
                try {
                    Test-DuplicateTunnel -RemoteHost $data.RemoteHost -RemotePort $data.RemotePort -LocalPort $data.LocalPort -ExcludeTunnelName $t.Name | Out-Null
                } catch {
                    $errors += $_.Exception.Message
                }
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
                if (-not [string]::IsNullOrWhiteSpace($data.Password)) { $params['PasswordPlain'] = $data.Password }
                Update-Tunnel @params | Out-Null
                Write-SSHXLog "Action: Tunnel updated"
                Update-TunnelListView
            } catch {
                Write-SSHXLog "Action: Edit failed - $_" -Level 'ERROR'
                [System.Windows.Forms.MessageBox]::Show("Edit failed: $_", 'sshx', 'OK', 'Error') | Out-Null
            }
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

    # Wire up buttons
    $btnAdd.Add_Click($script:addTunnel)
    $btnEdit.Add_Click($script:editTunnel)
    $btnDelete.Add_Click($script:deleteTunnel)
    $btnStart.Add_Click({ & $script:act 'Start' })
    $btnRestart.Add_Click({ & $script:act 'Restart' })
    $btnStop.Add_Click({ & $script:act 'Stop' })
    $btnRefresh.Add_Click({ Update-TunnelListView })
    $btnExport.Add_Click({ Export-Tunnels })
    
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
    $miEdit.Add_Click($script:editTunnel)
    $miDelete.Add_Click($script:deleteTunnel)

    # Double-click to edit
    $script:lv.Add_DoubleClick($script:editTunnel)

    # Load tunnels once when form opens (full status check)
    $f.Add_Load({ 
        Write-SSHXLog "UI: Form loaded"
        Update-TunnelListView
    })

    # Note: Buttons use Anchor property for automatic resize handling
    # ListView uses Anchor for auto-resize as well

    $f.Add_FormClosing({ 
        Write-SSHXLog "UI: Closing"
    })

    return $f
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

try {
    Get-PlinkPath | Out-Null
} catch {
    [System.Windows.Forms.MessageBox]::Show("$_`n`nInstall PuTTY and add plink to PATH.", 'sshx', 'OK', 'Error') | Out-Null
    exit 1
}

New-IntroForm | Out-Null
$main = New-MainForm
[System.Windows.Forms.Application]::Run($main)
