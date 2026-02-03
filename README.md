# sshx

**A lightweight SSH tunnel manager for Windows with a graphical interface.**

Create, manage, and monitor persistent SSH tunnels that automatically reconnect on network changes, VPN switches, or connection drops.

<!-- 
![sshx Main Window](screenshots/main-window.png)
TODO: Add screenshot of main window showing tunnel list with various statuses
-->

---

## Table of Contents

- [Why sshx?](#why-sshx)
- [Features](#features)
- [Use Cases](#use-cases)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Guide](#usage-guide)
- [Configuration](#configuration)
- [Security](#security)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [Project Structure](#project-structure)
- [Known Limitations](#known-limitations)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)

---

## Why sshx?

Managing SSH tunnels on Windows typically means:
- Running command-line ssh commands manually
- Writing batch scripts that don't handle reconnection
- Losing tunnels when switching WiFi or VPN
- Forgetting which tunnels are running

**sshx** solves these problems with a simple GUI that keeps your tunnels alive and reconnects them automatically.

| Traditional Approach | With sshx |
|---------------------|-----------|
| Manual ssh commands | Point-and-click GUI |
| Tunnels die on network change | Auto-reconnect in seconds |
| No visibility into status | Real-time status indicators |
| Passwords in plain text scripts | Encrypted with Windows DPAPI |
| Start tunnels manually after reboot | Quick restart with saved configs |

---

## Features

### Core Functionality
- **Graphical Interface** — No command-line knowledge required
- **Persistent Tunnels** — Tunnels keep running until you stop them
- **Auto-Reconnect** — Automatically reconnects on network/VPN changes with exponential backoff
- **Multiple Tunnels** — Manage as many tunnels as you need
- **No External Dependencies** — Uses Windows built-in OpenSSH client

### Authentication
- **Password Authentication** — Traditional username/password with DPAPI encryption
- **SSH Key Authentication** — Support for private key files (RSA, Ed25519, etc.)
- **Test Connection** — Verify credentials before saving a tunnel

### User Experience
- **Real-Time Status** — Visual indicators show tunnel health at a glance
  - 🟢 **Connected** — Tunnel is active and port is listening
  - 🟠 **Failing** — Runner active but tunnel not established
  - ⚫ **Stopped** — Tunnel is not running
- **Quick Actions** — Start, stop, restart with one click
- **Clone Tunnels** — Duplicate existing tunnels quickly
- **Keyboard Shortcuts** — F5 to refresh, double-click to edit
- **Context Menu** — Right-click for quick access to all actions
- **Log Viewer** — View runner logs directly in the UI

### Organization
- **Tunnel Groups** — Organize tunnels into groups (e.g., "Work", "Personal")

### Security
- **DPAPI Encryption** — Passwords encrypted using Windows Data Protection API
- **No Plain Text Storage** — Credentials never stored in readable format
- **Secure Export** — Exported configs exclude passwords
- **No Telemetry** — Completely offline, no data sent anywhere

### Management
- **Full CRUD** — Add, edit, delete, clone tunnel configurations
- **Import/Export** — Easy configuration backup and sharing
- **Auto-Start** — Option to run sshx at Windows startup
- **Configurable Timeout** — Set connection timeout per tunnel (5-300 seconds)
- **Validation** — Prevents duplicate ports and invalid configurations

<!-- 
![Tunnel Status Indicators](screenshots/tunnel-running.png)
TODO: Add screenshot showing connected tunnel with green status
-->

---

## Use Cases

### Database Access
Connect to remote databases through a bastion/jump host:
```
Local App → localhost:5432 → SSH Tunnel → Production PostgreSQL
Local App → localhost:3306 → SSH Tunnel → Production MySQL
Local App → localhost:1433 → SSH Tunnel → Production SQL Server
```

### Internal Services
Access internal company services while working remotely:
- Internal dashboards and admin panels
- Development/staging servers
- Internal APIs and microservices
- Monitoring tools (Grafana, Kibana, etc.)

### Development Workflows
- Connect IDE to remote debugging ports
- Access remote Redis/Memcached instances
- Tunnel to container services running on remote hosts

### Security & Compliance
- Access services without exposing them to the public internet
- Maintain encrypted connections to sensitive resources
- Audit trail through SSH server logs

---

## Requirements

| Requirement | Details |
|-------------|---------|
| **OS** | Windows 10/11 or Windows Server 2016+ |
| **PowerShell** | 5.1 or later (pre-installed on Windows 10+) |
| **OpenSSH** | Windows built-in OpenSSH client (usually pre-installed) |

### Enabling OpenSSH Client

The Windows OpenSSH client is typically pre-installed on Windows 10 (1809+) and Windows 11. To verify or enable it:

1. Open **Settings** > **Apps** > **Optional Features**
2. Search for "OpenSSH Client"
3. If not installed, click **Add a feature** and install "OpenSSH Client"

**Verify installation:**
```powershell
ssh -V
# Should output: OpenSSH_for_Windows_x.x.x.x, ...
```

---

## Installation

### Option 1: Clone Repository
```powershell
git clone https://github.com/YOUR_USERNAME/sshx.git
cd sshx
# Double-click sshx.vbs or run:
wscript sshx.vbs
```

### Option 2: Manual Download
1. Download all files from this repository
2. Keep the folder structure intact
3. Double-click `sshx.vbs` to launch

---

## Quick Start

1. **Launch** — Double-click `sshx.vbs`
2. **Add Tunnel** — Click the **Add** button
3. **Configure** — Fill in your SSH connection details:
   - **Name**: `My Database`
   - **Group** (optional): `Work`
   - **Remote Host**: `bastion.example.com`
   - **Remote Port**: `5432` (the service port on remote network)
   - **Local Port**: `15432` (where you'll connect locally)
   - **SSH Port**: `22`
   - **Username**: `your-ssh-user`
   - **Auth Method**: Choose Password or SSH Key
     - For Password: Enter your password
     - For SSH Key: Browse to your private key file (e.g., `~/.ssh/id_rsa`)
4. **Test** (optional) — Click **Test Connection** to verify credentials
5. **Save** — Click **Save**
6. **Start** — Select the tunnel and click **Start**
7. **Connect** — Your app can now connect to `localhost:15432`

<!-- 
![Add Tunnel Dialog](screenshots/add-tunnel-dialog.png)
TODO: Add screenshot of the Add Tunnel dialog with sample values
-->

---

## Usage Guide

### Main Window

The main window displays all configured tunnels in a list view:

| Column | Description |
|--------|-------------|
| **Name** | Your friendly name for the tunnel |
| **Status** | Current state (Connected/Failing/Stopped) |
| **Group** | Tunnel group for organization |
| **Local** | Local port number (localhost:PORT) |
| **Remote** | Remote host and port being forwarded |
| **Auth** | Authentication type (Pwd/Key) |
| **User** | SSH username |

### Toolbar Actions

| Button | Action | Keyboard |
|--------|--------|----------|
| **Add** | Create a new tunnel | — |
| **Edit** | Modify selected tunnel | Double-click |
| **Clone** | Duplicate selected tunnel | — |
| **Delete** | Remove selected tunnel | — |
| **Start** | Start the selected tunnel | — |
| **Restart** | Stop and restart tunnel | — |
| **Stop** | Stop the selected tunnel | — |
| **Log** | View runner log for tunnel | — |
| **Refresh** | Update status display | F5 |

### Menu Bar

| Menu | Options |
|------|---------|
| **File** | Import, Export, Exit |
| **Tools** | Run at Startup |
| **Help** | GitHub, About |

### Context Menu

Right-click any tunnel for quick access to:
- Start / Restart / Stop
- Edit / Clone / Delete
- View Log

### Understanding Tunnel Status

| Status | Color | Meaning | Action |
|--------|-------|---------|--------|
| **Connected** | Green | Tunnel active, port listening | Ready to use |
| **Starting...** | Orange | Tunnel being established | Wait a moment |
| **Failing** | Orange-Red | Runner active but can't connect | Check credentials/network |
| **Stopping...** | Gray | Tunnel being shut down | Wait a moment |
| **Stopped** | Black | Tunnel not running | Click Start |

---

## Configuration

### Storage Locations

| Item | Path |
|------|------|
| Tunnel configs | `%APPDATA%\SSHTunnelManager\tunnels.json` |
| Application log | `%APPDATA%\SSHTunnelManager\sshx.log` |
| Runner logs | `%TEMP%\sshx_runner_<name>.log` |

### Configuration File Format

The `tunnels.json` file contains your tunnel definitions:

```json
{
  "Tunnels": [
    {
      "Name": "Production DB",
      "RemoteHost": "bastion.example.com",
      "RemotePort": 5432,
      "LocalPort": 15432,
      "Username": "admin",
      "PasswordEncrypted": "<DPAPI encrypted string>",
      "SshPort": 22,
      "Pid": null,
      "AuthMethod": "password",
      "IdentityFile": "",
      "Group": "Work",
      "ConnectTimeout": 30
    }
  ]
}
```

| Field | Description |
|-------|-------------|
| `Name` | Unique tunnel identifier |
| `RemoteHost` | SSH server hostname or IP |
| `RemotePort` | Port to forward on remote side |
| `LocalPort` | Local port to listen on |
| `Username` | SSH username |
| `PasswordEncrypted` | DPAPI-encrypted password (for password auth) |
| `SshPort` | SSH server port (default: 22) |
| `AuthMethod` | `password` or `key` |
| `IdentityFile` | Path to SSH private key (for key auth) |
| `Group` | Optional group name for organization |
| `ConnectTimeout` | Connection timeout in seconds (5-300) |
| `Pid` | Runner process ID (managed by sshx) |

> **Note**: The `PasswordEncrypted` field can only be decrypted by the same Windows user account that created it.

### Backup & Migration

**To backup your tunnels:**
1. Use **File > Export** (excludes passwords for security)
2. Or copy `%APPDATA%\SSHTunnelManager\tunnels.json`

**To migrate to another machine:**
1. Export tunnels via **File > Export**
2. Copy the JSON file to the new machine
3. Use **File > Import** to load the tunnels
4. Edit each tunnel to re-enter passwords (DPAPI encryption is user-specific)
5. For SSH key auth, ensure the key files exist at the same paths

**Import Options:**
- **Skip existing** — Keep current tunnels if names match
- **Replace existing** — Overwrite current tunnels with imported ones

---

## Security

### Password Protection

sshx uses **Windows DPAPI (Data Protection API)** to encrypt passwords:

- Passwords are encrypted using your Windows user credentials
- The encrypted data can only be decrypted by the same Windows user account
- Even if someone copies your config file, they cannot decrypt the passwords without access to your Windows account
- Passwords are never logged or displayed in the UI

### Best Practices

1. **Use SSH keys when possible** — SSH keys are more secure than passwords for production environments
2. **Protect your private keys** — Use a passphrase on your SSH keys and store them securely
3. **Don't share config files** — The `tunnels.json` contains encrypted passwords tied to your account
4. **Use strong passwords** — The encryption is only as strong as your credentials
5. **Keep Windows updated** — Security patches are released periodically

### What sshx Does NOT Do

- Does not store passwords in plain text
- Does not send any data over the network (except SSH connections)
- Does not include telemetry or analytics
- Does not require admin privileges
- Does not modify system settings

---

## Troubleshooting

### "ssh.exe not found" Error

**Problem**: sshx can't find the OpenSSH client.

**Solution**:
1. Check if OpenSSH is installed:
   ```powershell
   ssh -V
   ```
2. If not found, enable OpenSSH Client:
   - Open **Settings** > **Apps** > **Optional Features**
   - Click **Add a feature**
   - Search for and install "OpenSSH Client"
3. Restart sshx after installation

### Host Key Verification Failed

**Problem**: First connection to a new server fails with host key error.

**Solution**: Accept the host key manually first:
```powershell
ssh -p 22 username@hostname
# When prompted, type 'yes' to accept and store the host key
# Then close the connection (Ctrl+C or type 'exit')
```

> **Note**: sshx uses `-o StrictHostKeyChecking=accept-new` which auto-accepts new host keys but will reject changed keys for security.

### Tunnel Shows "Failing" Status

**Problem**: Runner is active but tunnel won't connect.

**Diagnosis**:
1. Check the runner log: `%TEMP%\sshx_runner_<tunnelname>.log`
2. Common causes:
   - Wrong password
   - Server not reachable
   - SSH port blocked by firewall
   - Host key changed (security warning)

### Port Already in Use

**Problem**: Can't start tunnel because local port is in use.

**Solution**:
1. Choose a different local port
2. Or find and stop the process using that port:
   ```powershell
   netstat -ano | findstr :5432
   # Note the PID (last column)
   taskkill /PID <pid> /F
   ```

### Tunnel Disconnects Frequently

**Problem**: Tunnel keeps dropping and reconnecting.

**Possible causes**:
- Unstable network connection
- SSH server timeout settings
- Firewall or proxy interference

**Solutions**:
- Check your network stability
- Ask server admin to increase `ClientAliveInterval` on the SSH server
- Check if corporate firewall/proxy is interfering

> **Note**: sshx uses `ServerAliveInterval=30` and `ServerAliveCountMax=3` to detect dead connections quickly.

---

## FAQ

### Can I use SSH keys instead of passwords?

Yes! sshx supports both password and SSH key authentication. When adding or editing a tunnel, select "SSH Key" as the auth method and browse to your private key file.

Common key locations:
- `%USERPROFILE%\.ssh\id_rsa` (RSA)
- `%USERPROFILE%\.ssh\id_ed25519` (Ed25519)

### Will my tunnels survive a Windows restart?

The tunnels themselves won't auto-start after reboot, but your configurations are saved. You have two options:
1. Launch sshx manually and start the tunnels you need
2. Enable auto-start via **Tools > Run at Windows Startup** to launch sshx automatically at login

### Can I run sshx at Windows startup?

Yes! Go to **Tools > Run at Windows Startup** to enable/disable auto-start. This creates a shortcut in your Windows Startup folder.

### How many tunnels can I run simultaneously?

There's no hard limit. Each tunnel runs as a separate process, so system resources (memory, handles) are the only constraint. Most users run 5-15 tunnels without issues.

### Is this safe for corporate/enterprise use?

Yes. sshx:
- Stores data locally only (no cloud)
- Uses Windows-native encryption (DPAPI)
- Has no telemetry or external connections
- Works behind corporate firewalls/proxies (as long as SSH is allowed)

### Can I use this with SSH bastion/jump hosts?

Yes, sshx works with any SSH server. Configure the Remote Host as your bastion server, and set the Remote Port to the service port accessible from that bastion.

### Why use Windows OpenSSH?

sshx uses the Windows built-in OpenSSH client which:
- Comes pre-installed on modern Windows (10/11)
- Requires no external dependencies like PuTTY
- Is maintained and updated by Microsoft
- Supports standard SSH features and configuration

---

## Project Structure

```
sshx/
├── sshx.vbs                    # Windows launcher (entry point, no console window)
├── README.md                   # This file
├── LICENSE                     # License file
├── screenshots/                # Screenshots for documentation
│   └── .gitkeep
└── src/
    ├── sshx.ps1                # Main GUI application (Windows Forms)
    ├── SSHTunnelCore.psm1      # Core module (CRUD, encryption, tunnel operations)
    └── SSHTunnelRunner.ps1     # Background process with auto-reconnect
```

### Component Overview

| File | Purpose |
|------|---------|
| `sshx.vbs` | VBScript launcher that starts PowerShell without showing a console window |
| `sshx.ps1` | Windows Forms GUI with intro screen and main window |
| `SSHTunnelCore.psm1` | Core logic: config management, DPAPI encryption, tunnel start/stop |
| `SSHTunnelRunner.ps1` | Background runner that keeps SSH tunnel alive and handles network changes |

### How It Works

1. **Launcher** (`sshx.vbs`) starts PowerShell hidden (no console window)
2. **GUI** (`sshx.ps1`) shows the main interface with tunnel list
3. **Start Tunnel** spawns a background **Runner** (`SSHTunnelRunner.ps1`)
4. **Runner** uses `ssh.exe` with local port forwarding (`-L`) and:
   - Uses `SSH_ASKPASS` mechanism for password authentication
   - Uses `-i` flag for SSH key authentication
   - Monitors network changes (WiFi/VPN) and auto-reconnects
   - Uses exponential backoff for retries (5s → 10s → 20s → 40s → 60s max)
   - Resets backoff after stable connections (>60 seconds)
   - Keeps trying until stopped or tunnel config is deleted

---

## Known Limitations

| Limitation | Details | Workaround |
|------------|---------|------------|
| No portable mode | Config stored in %APPDATA% | Use Export/Import for backup |
| Windows only | Requires Windows + PowerShell | Use native SSH on Linux/Mac |
| Single user | Config tied to Windows user | Each user maintains own tunnels |
| No jump host | Direct SSH only | Use ProxyJump in ~/.ssh/config |
| Passphrase keys | Keys with passphrases require ssh-agent | Use ssh-agent or passphrase-less keys |

---

## Contributing

Contributions are welcome! Here's how you can help:

1. **Report bugs** — Open an issue with steps to reproduce
2. **Suggest features** — Open an issue with your idea
3. **Submit PRs** — Fork, make changes, submit a pull request

### Development Setup

1. Clone the repository
2. Ensure Windows OpenSSH is installed
3. Run `wscript sshx.vbs` or launch `sshx.ps1` directly in PowerShell
4. Check logs in `%APPDATA%\SSHTunnelManager\` for debugging

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## Acknowledgments

- **Windows OpenSSH** — The SSH client that powers the tunnels
- **Windows Forms** — Microsoft's UI framework for desktop applications

---

<p align="center">
  <b>sshx</b> — SSH tunnels made simple
</p>
