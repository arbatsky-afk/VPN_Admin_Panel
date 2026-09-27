[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet("Install", "Remove", "Status")]
    [string]$Action = "Status"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$TaskName = "VPN Admin Desktop"
$TaskPath = "\"
$ProjectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$LauncherPath = Join-Path $ProjectRoot "run-desktop-suite.vbs"
$WscriptPath = Join-Path $env:SystemRoot "System32\wscript.exe"
$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$LauncherArguments = '//Nologo "{0}"' -f $LauncherPath

function Get-DesktopAutostartTask {
    Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
}

function Write-DesktopAutostartStatus {
    $task = Get-DesktopAutostartTask
    if ($null -eq $task) {
        Write-Output "Desktop autostart is not installed."
        return
    }

    $trigger = @($task.Triggers)[0]
    $taskAction = @($task.Actions)[0]
    [pscustomobject]@{
        TaskName = $task.TaskName
        State = $task.State
        User = $task.Principal.UserId
        LogonType = $task.Principal.LogonType
        RunLevel = $task.Principal.RunLevel
        TriggerUser = $trigger.UserId
        Delay = $trigger.Delay
        MultipleInstances = $task.Settings.MultipleInstances
        Execute = $taskAction.Execute
        Arguments = $taskAction.Arguments
        WorkingDirectory = $taskAction.WorkingDirectory
    } | Format-List
}

switch ($Action) {
    "Install" {
        if (-not (Test-Path -LiteralPath $LauncherPath -PathType Leaf)) {
            throw "Desktop suite launcher was not found: $LauncherPath"
        }
        if (-not (Test-Path -LiteralPath $WscriptPath -PathType Leaf)) {
            throw "Windows Script Host was not found: $WscriptPath"
        }

        $taskAction = New-ScheduledTaskAction `
            -Execute $WscriptPath `
            -Argument $LauncherArguments `
            -WorkingDirectory $ProjectRoot
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User $CurrentUser
        $trigger.Delay = "PT15S"
        $principal = New-ScheduledTaskPrincipal `
            -UserId $CurrentUser `
            -LogonType Interactive `
            -RunLevel Limited
        $settings = New-ScheduledTaskSettingsSet `
            -MultipleInstances IgnoreNew `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -StartWhenAvailable `
            -ExecutionTimeLimit (New-TimeSpan -Minutes 1)

        Register-ScheduledTask `
            -TaskName $TaskName `
            -TaskPath $TaskPath `
            -Description "Starts VPN Monitor and VPN Admin Panel after the current user logs on." `
            -Action $taskAction `
            -Trigger $trigger `
            -Principal $principal `
            -Settings $settings `
            -Force | Out-Null

        Write-Output "Desktop autostart was installed."
        Write-DesktopAutostartStatus
    }
    "Remove" {
        if ($null -eq (Get-DesktopAutostartTask)) {
            Write-Output "Desktop autostart is not installed."
            break
        }
        Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false
        Write-Output "Desktop autostart was removed."
    }
    "Status" {
        Write-DesktopAutostartStatus
    }
}
