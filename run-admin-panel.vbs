Option Explicit

Dim shell, fileSystem, projectRoot, pythonPath

Set shell = CreateObject("WScript.Shell")
Set fileSystem = CreateObject("Scripting.FileSystemObject")

projectRoot = fileSystem.GetParentFolderName(WScript.ScriptFullName)
pythonPath = projectRoot & "\.venv\Scripts\python.exe"

If Not fileSystem.FileExists(pythonPath) Then
    WScript.Echo "Python virtual environment was not found. See docs\Инструкции\01 — Запуск desktop-панели.md"
    WScript.Quit 1
End If

shell.CurrentDirectory = projectRoot
shell.Run """" & pythonPath & """ -m app", 0, False
