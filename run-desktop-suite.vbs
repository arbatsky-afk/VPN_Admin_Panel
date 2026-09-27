Option Explicit

Dim shell, fileSystem, projectRoot, wscriptPath, monitorLauncher, panelLauncher

Set shell = CreateObject("WScript.Shell")
Set fileSystem = CreateObject("Scripting.FileSystemObject")

projectRoot = fileSystem.GetParentFolderName(WScript.ScriptFullName)
wscriptPath = shell.ExpandEnvironmentStrings("%SystemRoot%") & "\System32\wscript.exe"
monitorLauncher = projectRoot & "\run-monitor.vbs"
panelLauncher = projectRoot & "\run-admin-panel.vbs"

If Not fileSystem.FileExists(wscriptPath) Then
    WScript.Echo "Windows Script Host was not found."
    WScript.Quit 1
End If

If Not fileSystem.FileExists(monitorLauncher) Or Not fileSystem.FileExists(panelLauncher) Then
    WScript.Echo "VPN Monitor or VPN Admin launcher was not found."
    WScript.Quit 1
End If

shell.CurrentDirectory = projectRoot
shell.Run Quote(wscriptPath) & " //Nologo " & Quote(monitorLauncher), 0, False
WScript.Sleep 1000
shell.Run Quote(wscriptPath) & " //Nologo " & Quote(panelLauncher), 0, False

Function Quote(value)
    Quote = Chr(34) & value & Chr(34)
End Function
