<#
.SYNOPSIS
Safely checks key-based SSH connectivity to a managed VPN server.

.DESCRIPTION
Makes no changes on the remote server. The only remote command is `true`.
The server must already have a trusted SSH host key in the current user's
known_hosts file. SSH settings are read from runtime/panel/settings.json.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [string]$ServerIp
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = $utf8NoBom
$OutputEncoding = $utf8NoBom

try {
    $parsedIp = [System.Net.IPAddress]::Parse($ServerIp)
}
catch {
    throw "ServerIp must be a valid IPv4 address: $ServerIp"
}

if ($parsedIp.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
    throw "Only an IPv4 address is supported: $ServerIp"
}

if (-not (Get-Command ssh -ErrorAction SilentlyContinue)) {
    throw 'Required command is not available: ssh'
}

$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
Import-Module (Join-Path $PSScriptRoot 'lib\ssh-settings.psm1') -Force
$privateKey = Get-PrimarySshPrivateKey -ProjectRoot $projectRoot
$sshPort = Get-ConfiguredSshPort -ProjectRoot $projectRoot

$target = "root@$ServerIp"
$sshArguments = @(
    '-o', 'BatchMode=yes',
    '-o', 'ConnectTimeout=15',
    '-o', 'ServerAliveInterval=5',
    '-o', 'ServerAliveCountMax=3',
    '-o', 'PreferredAuthentications=publickey',
    '-o', 'PasswordAuthentication=no',
    '-o', 'KbdInteractiveAuthentication=no',
    '-o', 'StrictHostKeyChecking=yes',
    '-o', 'IdentitiesOnly=yes',
    '-i', $privateKey,
    '-p', $sshPort,
    $target,
    'true'
)

Write-Output "Checking SSH connectivity to $target ..."
$sshOutput = @(& ssh @sshArguments 2>&1)
$exitCode = $LASTEXITCODE

if ($exitCode -ne 0) {
    $details = ($sshOutput | Out-String).Trim()
    if ($details -match '(?i)host key|known host|identification has changed') {
        throw "SSH host-key verification failed for $target. Verify the server fingerprint in known_hosts. $details"
    }

    if ([string]::IsNullOrWhiteSpace($details)) {
        $details = 'The SSH client returned no diagnostic output.'
    }

    throw "SSH connectivity check failed for $target (exit code $exitCode). $details"
}

Write-Output "SSH connectivity check succeeded: $target"
