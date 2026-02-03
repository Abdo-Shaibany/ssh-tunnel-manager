' sshx.vbs - Launches sshx without showing any console window
' Double-click this file to start the SSH Tunnel Manager

Set objShell = CreateObject("WScript.Shell")
strPath = CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName)
strCommand = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & strPath & "\src\sshx.ps1"""
objShell.Run strCommand, 0, False
