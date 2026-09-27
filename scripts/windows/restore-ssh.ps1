<#
.SYNOPSIS
Restores SSH key access to a freshly reinstalled Ubuntu server.

.DESCRIPTION
The private-key paths are read from runtime/panel/settings.json. The script remains intentionally interactive because
the provider-issued root password is entered by the operator once.

.EXAMPLE
.\restore-ssh.ps1 203.0.113.10
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [string]$ServerIp
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-Ssh {
    param(
        [Parameter(Mandatory)]
        [ValidateRange(1, 65535)]
        [int]$Port,

        [string[]]$Arguments,
        [string]$FailureMessage
    )

    & ssh `
        '-o' 'ConnectTimeout=15' `
        '-o' 'ServerAliveInterval=5' `
        '-o' 'ServerAliveCountMax=3' `
        '-p' ([string]$Port) `
        @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw $FailureMessage
    }
}

function New-SshFixKnownHostsCopy {
    param(
        [string]$KnownHostsPath,
        [string]$KnownHostsKey
    )

    $sshDirectory = Split-Path -Parent $KnownHostsPath
    if (-not (Test-Path -LiteralPath $sshDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $sshDirectory -Force | Out-Null
    }

    $temporaryName = '.known_hosts.ssh-fix-{0}.tmp' -f [guid]::NewGuid()
    $temporaryPath = Join-Path $sshDirectory $temporaryName
    if (Test-Path -LiteralPath $KnownHostsPath -PathType Leaf) {
        Copy-Item -LiteralPath $KnownHostsPath -Destination $temporaryPath
        & ssh-keygen '-R' $KnownHostsKey '-f' $temporaryPath | Out-Null
    }
    else {
        New-Item -ItemType File -Path $temporaryPath | Out-Null
    }
    return $temporaryPath
}

function Install-AcceptedKnownHosts {
    param(
        [string]$TemporaryPath,
        [string]$KnownHostsPath
    )

    if (Test-Path -LiteralPath $KnownHostsPath -PathType Leaf) {
        $backupName = '.known_hosts.ssh-fix-{0}.bak' -f [guid]::NewGuid()
        $backupPath = Join-Path (Split-Path -Parent $KnownHostsPath) $backupName
        [System.IO.File]::Replace($TemporaryPath, $KnownHostsPath, $backupPath, $true)
        Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue
    }
    else {
        Move-Item -LiteralPath $TemporaryPath -Destination $KnownHostsPath
    }
}

try {
    $parsedIp = [System.Net.IPAddress]::Parse($ServerIp)
}
catch {
    throw "ServerIp must be a valid IPv4 address: $ServerIp"
}
if ($parsedIp.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
    throw "Only an IPv4 address is supported: $ServerIp"
}

$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
Import-Module (Join-Path $PSScriptRoot 'lib\ssh-settings.psm1') -Force
try {
    $sshPort = Get-ConfiguredSshPort -ProjectRoot $projectRoot
}
catch {
    throw 'Could not read the SSH port from Admin Panel Settings. Check SSH port in Settings.'
}
$privateKey = Get-PrimarySshPrivateKey -ProjectRoot $projectRoot
$sshFixPrivateKeys = @(Get-SshFixPrivateKeys -ProjectRoot $projectRoot)

foreach ($command in 'ssh', 'ssh-keygen') {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "Required command is not available: $command"
    }
}

$publicKeysText = @(
    foreach ($keyPath in $sshFixPrivateKeys) {
        $publicKey = "$keyPath.pub"
        if (-not (Test-Path -LiteralPath $publicKey -PathType Leaf)) {
            throw "SSH public key is missing: $publicKey"
        }
        $publicKeyText = (Get-Content -LiteralPath $publicKey -Raw -Encoding utf8).Trim()
        if ($publicKeyText -notmatch '^ssh-(ed25519|rsa)\s+\S+(\s+.*)?$') {
            throw "Unexpected public-key format in: $publicKey"
        }
        $publicKeyText
    }
) -join "`n"

$target = "root@$ServerIp"
$bootstrapScript = @'
set -eu
install -d -m 700 /root/.ssh
touch /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
while IFS= read -r key; do
  if [ -n "$key" ] && ! grep -qxF "$key" /root/.ssh/authorized_keys; then
    printf '%s\n' "$key" >> /root/.ssh/authorized_keys
  fi
done <<'AUTHORIZED_KEYS'
__PUBLIC_KEYS__
AUTHORIZED_KEYS
chown -R root:root /root/.ssh
'@
$bootstrapScript = $bootstrapScript.Replace('__PUBLIC_KEYS__', $publicKeysText)
$bootstrapBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($bootstrapScript))
$bootstrapCommand = "printf '%s' '$bootstrapBase64' | base64 -d | bash"

$knownHosts = Join-Path $env:USERPROFILE '.ssh\known_hosts'
$knownHostsKey = if ($sshPort -eq 22) { $ServerIp } else { '[{0}]:{1}' -f $ServerIp, $sshPort }
$temporaryKnownHosts = New-SshFixKnownHostsCopy -KnownHostsPath $knownHosts -KnownHostsKey $knownHostsKey
try {
    Write-Host ("SSH Fix target: {0}:{1}" -f $ServerIp, $sshPort)
    Write-Host 'Open the provider panel or trusted web/VNC/serial console and obtain the server SSH host-key fingerprint.'
    Write-Host 'Compare it exactly with the fingerprint shown by OpenSSH below. Type yes only when they match.'
    Write-Host 'OpenSSH will ask for the new provider-issued root password only after you accept the verified host key.'
    Invoke-Ssh -Port $sshPort -Arguments @(
        '-o', 'PreferredAuthentications=password,keyboard-interactive',
        '-o', 'PubkeyAuthentication=no',
        '-o', 'StrictHostKeyChecking=ask',
        '-o', "UserKnownHostsFile=$temporaryKnownHosts",
        '-o', 'UpdateHostKeys=no',
        $target,
        $bootstrapCommand
    ) -FailureMessage 'Could not add the SSH public key. Reject an unverified fingerprint; otherwise check the server IP and provider password.'

    Install-AcceptedKnownHosts -TemporaryPath $temporaryKnownHosts -KnownHostsPath $knownHosts
}
finally {
    foreach ($temporaryPath in $temporaryKnownHosts, "$temporaryKnownHosts.old") {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
    }
}

Write-Host 'Checking SSH key access...'
Invoke-Ssh -Port $sshPort -Arguments @(
    '-o', 'BatchMode=yes',
    '-o', 'PreferredAuthentications=publickey',
    '-o', 'PasswordAuthentication=no',
    '-o', 'KbdInteractiveAuthentication=no',
    '-o', 'StrictHostKeyChecking=yes',
    '-o', "UserKnownHostsFile=$knownHosts",
    '-o', 'UpdateHostKeys=no',
    '-o', 'IdentitiesOnly=yes',
    '-i', $privateKey,
    $target,
    'true'
) -FailureMessage "SSH key access failed. Add the key to ssh-agent with: ssh-add $privateKey"

$hardeningScript = @'
set -eu
test -d /etc/ssh/sshd_config.d || {
  echo 'The Ubuntu SSH configuration directory sshd_config.d is missing.' >&2
  exit 1
}
backup_dir=/root/ssh-recovery-backups
dropin=/etc/ssh/sshd_config.d/00-vpn-key-only.conf
install -d -m 700 "$backup_dir"
backup=
if [ -f "$dropin" ]; then
  backup="$backup_dir/00-vpn-key-only.conf.$(date +%Y%m%d-%H%M%S).bak"
  cp -a "$dropin" "$backup"
fi
restore_previous() {
  if [ -n "$backup" ]; then
    cp -a "$backup" "$dropin"
  else
    rm -f "$dropin"
  fi
}
cat > "$dropin" <<'EOF'
# Managed by restore-ssh.ps1
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
EOF
if ! sshd -t; then
  restore_previous
  echo 'The new SSH configuration is invalid; password access was not changed.' >&2
  exit 1
fi
if ! sshd -T | grep -qx 'passwordauthentication no'; then
  restore_previous
  echo 'The SSH drop-in was not applied; password access was not changed.' >&2
  exit 1
fi
if ! systemctl reload ssh; then
  restore_previous
  systemctl reload ssh || true
  echo 'SSH could not reload the new SSH configuration; the previous configuration was restored.' >&2
  exit 1
fi
'@
$hardeningBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($hardeningScript))
$hardeningCommand = "printf '%s' '$hardeningBase64' | base64 -d | bash"

Write-Host 'Disabling password SSH access...'
Invoke-Ssh -Port $sshPort -Arguments @(
    '-o', 'BatchMode=yes',
    '-o', 'PreferredAuthentications=publickey',
    '-o', 'PasswordAuthentication=no',
    '-o', 'KbdInteractiveAuthentication=no',
    '-o', 'StrictHostKeyChecking=yes',
    '-o', "UserKnownHostsFile=$knownHosts",
    '-o', 'UpdateHostKeys=no',
    '-o', 'IdentitiesOnly=yes',
    '-i', $privateKey,
    $target,
    $hardeningCommand
) -FailureMessage 'SSH hardening failed. Password access may still be enabled; use the provider console if needed.'

Write-Host 'Checking final SSH key access...'
Invoke-Ssh -Port $sshPort -Arguments @(
    '-o', 'BatchMode=yes',
    '-o', 'PreferredAuthentications=publickey',
    '-o', 'PasswordAuthentication=no',
    '-o', 'KbdInteractiveAuthentication=no',
    '-o', 'StrictHostKeyChecking=yes',
    '-o', "UserKnownHostsFile=$knownHosts",
    '-o', 'UpdateHostKeys=no',
    '-o', 'IdentitiesOnly=yes',
    '-i', $privateKey,
    $target,
    'true'
) -FailureMessage 'Final SSH verification failed. Use the provider console before closing any access session.'

Write-Host "SSH access restored and password authentication disabled on $target!"
