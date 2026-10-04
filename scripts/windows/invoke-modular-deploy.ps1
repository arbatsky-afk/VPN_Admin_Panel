<#
.SYNOPSIS
Copies the modular deployment bundle to a unique temporary server directory and
runs one approved component.

.DESCRIPTION
The launcher receives validated immutable Component inputs from the Python
application and reads SSH connection settings from runtime/panel/settings.json.
It does not read application defaults or legacy deployment configuration.
Component configuration is written to a temporary config.env file and copied to
the staging directory; it is never interpolated into an SSH shell command. For
Netdata this file temporarily contains the validated Cloud claim token and Room
IDs from runtime/panel/settings.json.
Every staged file is verified against a locally generated SHA-256 manifest before
the installer starts. The server directory is removed on every exit path.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [string]$ServerIp,

    [Parameter(Mandatory, Position = 1)]
    [ValidateSet('base-security', 'xray', 'hysteria2', 'mieru', 'docker', 'nginx', 'netdata')]
    [string]$Component,

    [Parameter(Mandatory, Position = 2)]
    [string]$BundleDirectory,

    [Parameter(Mandatory, Position = 3)]
    [string]$ComponentInputsBase64
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = $utf8NoBom
$OutputEncoding = $utf8NoBom

function Get-RequiredConfigValue {
    param(
        [Parameter(Mandatory)]
        [object]$Object,

        [Parameter(Mandatory)]
        [string]$PropertyName,

        [Parameter(Mandatory)]
        [string]$DisplayName
    )

    if ($null -eq $Object) {
        throw "Required configuration is missing $DisplayName."
    }
    $property = $Object.PSObject.Properties[$PropertyName]
    if ($null -eq $property -or $null -eq $property.Value) {
        throw "Required configuration is missing $DisplayName."
    }
    return $property.Value
}

function Get-ValidatedComponentInputs {
    param(
        [Parameter(Mandatory)]
        [string]$ComponentName,

        [Parameter(Mandatory)]
        [string]$EncodedInputs
    )

    try {
        $json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($EncodedInputs))
        $inputs = $json | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw 'Validated Component inputs are not valid base64-encoded JSON.'
    }
    if ($inputs -isnot [PSCustomObject]) {
        throw 'Validated Component inputs must contain one JSON object.'
    }
    $expectedFields = @(switch ($ComponentName) {
        'xray' { @('XRAY_PORT_RANGE_START', 'XRAY_PORT_RANGE_END', 'MASQUERADE_HOST') }
        'hysteria2' { @('HYSTERIA_PORT_RANGE_START', 'HYSTERIA_PORT_RANGE_END', 'HYSTERIA_INITIAL_USER', 'HYSTERIA_CERTIFICATE_DAYS', 'HYSTERIA_BANDWIDTH_UP', 'HYSTERIA_BANDWIDTH_DOWN', 'HYSTERIA_MASQUERADE_HOST') }
        'mieru' { @('MIERU_PORT_RANGE_START', 'MIERU_PORT_RANGE_END', 'MIERU_PROTOCOL', 'MIERU_MTU', 'MIERU_INITIAL_USER') }
        'nginx' { @('NGINX_TLS_MODE', 'NGINX_SERVER_NAME') }
        default { @() }
    })
    $actualFields = @($inputs.PSObject.Properties | ForEach-Object { $_.Name })
    if (
        $actualFields.Count -ne $expectedFields.Count -or
        @($actualFields | Where-Object { $_ -notin $expectedFields }).Count -ne 0
    ) {
        throw "Validated Component inputs do not match the $ComponentName Deploy contract."
    }
    foreach ($field in $expectedFields) {
        $value = $inputs.PSObject.Properties[$field].Value
        if ($value -isnot [string] -or $value -match '[\r\n"`$]') {
            throw "Validated Component input $field is unsafe."
        }
    }
    return $inputs
}

try {
    $parsedIp = [System.Net.IPAddress]::Parse($ServerIp)
}
catch {
    throw 'ServerIp must be a valid IPv4 address.'
}
if ($parsedIp.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
    throw 'Only an IPv4 address is supported.'
}

$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
Import-Module (Join-Path $PSScriptRoot 'lib\ssh-settings.psm1') -Force
$componentInputs = Get-ValidatedComponentInputs $Component $ComponentInputsBase64
$privateKey = Get-PrimarySshPrivateKey -ProjectRoot $projectRoot
$resolvedProjectRoot = [IO.Path]::GetFullPath($projectRoot)
$bundleDirectory = [IO.Path]::GetFullPath($BundleDirectory)
$projectPrefix = "$resolvedProjectRoot$([IO.Path]::DirectorySeparatorChar)"
if (-not $bundleDirectory.StartsWith($projectPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Validated modular deployment bundle must stay inside the project directory.'
}
if (-not (Test-Path -LiteralPath $bundleDirectory -PathType Container)) {
    throw 'The modular deployment bundle directory is missing.'
}

$requiredPaths = @('install-component.sh', 'lib\common.sh', 'lib\state.sh', 'lib\firewall.sh', 'lib\port_contract.py', 'lib\component_registry.py', 'lib\component_declaration.py')
switch ($Component) {
    'base-security' {
        $requiredPaths += 'components\base-security.sh', 'assets\declarations\base-security.json', 'assets\declarations\SHA256SUMS', 'templates\nftables.conf.tmpl', 'templates\10-base.nft.tmpl', 'templates\fail2ban-jail.local.tmpl'
    }
    'xray' {
        $requiredPaths += 'components\xray.sh', 'assets\SHA256SUMS', 'assets\xray\Xray-linux-64-v26.6.27.zip', 'assets\declarations\xray.json', 'assets\declarations\SHA256SUMS', 'templates\xray-config.json.tmpl', 'templates\xray.service.tmpl', 'templates\20-xray.nft.tmpl'
    }
    'hysteria2' {
        $requiredPaths += 'components\hysteria2.sh', 'lib\hysteria2_config.py', 'assets\SHA256SUMS', 'assets\hysteria2\hysteria-linux-amd64-v2.9.2', 'assets\declarations\hysteria2.json', 'assets\declarations\SHA256SUMS', 'templates\hysteria-config.yaml.tmpl', 'templates\hysteria-server.service.tmpl', 'templates\30-hysteria2.nft.tmpl'
    }
    'mieru' {
        $requiredPaths += 'components\mieru.sh', 'lib\mieru_config.py', 'assets\SHA256SUMS', 'assets\mita\mita_3.35.0_amd64.deb', 'assets\declarations\mieru.json', 'assets\declarations\SHA256SUMS', 'templates\40-mieru.nft.tmpl'
    }
    'docker' {
        $requiredPaths += 'components\docker.sh', 'assets\declarations\docker.json', 'assets\declarations\SHA256SUMS'
    }
    'nginx' {
        $requiredPaths += 'components\nginx.sh', 'lib\nginx_contract.py', 'assets\declarations\nginx.json', 'assets\declarations\SHA256SUMS', 'templates\nginx-site.conf.tmpl', 'templates\nginx-letsencrypt-site.conf.tmpl', 'templates\nginx-index.html.tmpl', 'templates\nginx-renew.sh.tmpl', 'templates\vpn-admin-nginx-renew.service.tmpl', 'templates\vpn-admin-nginx-renew.timer.tmpl', 'templates\50-nginx.nft.tmpl'
    }
    'netdata' {
        $requiredPaths += 'components\netdata.sh', 'assets\declarations\netdata.json', 'assets\declarations\nginx.json', 'assets\declarations\SHA256SUMS', 'templates\netdata.conf.tmpl', 'templates\netdata-location.conf.tmpl'
    }
}
foreach ($requiredPath in $requiredPaths) {
    if (-not (Test-Path -LiteralPath (Join-Path $bundleDirectory $requiredPath) -PathType Leaf)) {
        throw "The modular deployment bundle is incomplete: $requiredPath is missing."
    }
}

$bundleName = Split-Path -Leaf $bundleDirectory
if ($bundleName -notmatch '^[A-Za-z0-9._-]+$') {
    throw 'The modular deployment bundle directory name contains unsupported characters.'
}

try {
    $sshPort = Get-ConfiguredSshPort -ProjectRoot $projectRoot
}
catch {
    throw "Panel SSH configuration is invalid: $($_.Exception.Message)"
}

function Get-NetdataCloudSettings {
    param(
        [Parameter(Mandatory)]
        [string]$SettingsPath
    )

    Write-Host 'Netdata Cloud preflight: fill or verify Claim token and Claim rooms in Admin Panel Settings > Netdata.'
    if (-not (Test-Path -LiteralPath $SettingsPath -PathType Leaf)) {
        throw 'Panel settings are missing. Start the panel once, then fill Netdata Cloud settings.'
    }
    try {
        $panelSettings = Get-Content -LiteralPath $SettingsPath -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw 'Panel settings contain invalid JSON.'
    }
    $cloud = Get-RequiredConfigValue $panelSettings 'netdata_cloud' 'netdata_cloud'
    if ($cloud -isnot [PSCustomObject]) {
        throw 'Panel Netdata Cloud settings are invalid.'
    }
    $claimToken = [string](Get-RequiredConfigValue $cloud 'claim_token' 'netdata_cloud.claim_token')
    $claimRooms = [string](Get-RequiredConfigValue $cloud 'claim_rooms' 'netdata_cloud.claim_rooms')
    if ([string]::IsNullOrWhiteSpace($claimToken)) {
        throw 'Fill Claim token in Admin Panel Settings > Netdata before Deploy Netdata.'
    }
    if ($claimToken -notmatch '^[A-Za-z0-9_-]{20,1024}$') {
        throw 'netdata_cloud.claim_token has an invalid format.'
    }
    $roomIdPattern = '[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}'
    if (-not [string]::IsNullOrEmpty($claimRooms) -and $claimRooms -notmatch "^$roomIdPattern(?:,$roomIdPattern)*$") {
        throw 'netdata_cloud.claim_rooms must be empty or a comma-separated list of Room IDs.'
    }
    return [PSCustomObject]@{ ClaimToken = $claimToken; ClaimRooms = $claimRooms }
}

$configLines = [System.Collections.Generic.List[string]]::new()
$configLines.Add('TARGET_OS="ubuntu-24.04"')
$configLines.Add('TARGET_ARCH="amd64"')
$configLines.Add("SSH_PORT=`"$sshPort`"")
$configLines.Add("SERVER_ADDRESS=`"$($parsedIp.ToString())`"")
foreach ($property in $componentInputs.PSObject.Properties) {
    $configLines.Add("$($property.Name)=`"$([string]$property.Value)`"")
}
if ($Component -eq 'netdata') {
    $panelSettingsPath = Get-PanelSettingsPath -ProjectRoot $projectRoot
    $netdataCloud = Get-NetdataCloudSettings $panelSettingsPath
    $configLines.Add("NETDATA_CLAIM_TOKEN=`"$($netdataCloud.ClaimToken)`"")
    $configLines.Add("NETDATA_CLAIM_ROOMS=`"$($netdataCloud.ClaimRooms)`"")
}

foreach ($command in 'scp', 'ssh') {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "Required command is not available: $command"
    }
}

$target = "root@$ServerIp"
$sshOptions = @(
    '-o', 'BatchMode=yes',
    '-o', 'ConnectTimeout=15',
    '-o', 'ServerAliveInterval=15',
    '-o', 'ServerAliveCountMax=4',
    '-o', 'IdentitiesOnly=yes',
    '-o', 'StrictHostKeyChecking=yes',
    '-i', $privateKey,
    '-p', $sshPort
)
$scpOptions = @(
    '-o', 'BatchMode=yes',
    '-o', 'ConnectTimeout=15',
    '-o', 'ServerAliveInterval=15',
    '-o', 'ServerAliveCountMax=4',
    '-o', 'IdentitiesOnly=yes',
    '-o', 'StrictHostKeyChecking=yes',
    '-i', $privateKey,
    '-P', $sshPort
)

$temporaryConfig = $null
$temporaryManifest = $null
$temporaryBundleRoot = $null
$stagedBundleDirectory = $null
$remoteStage = "/root/.vpn-deploy-$([guid]::NewGuid().ToString('N'))"
$remoteBundle = "$remoteStage/$bundleName"
$remoteCleanupRequired = $false
$operationError = $null
$remoteCleanupError = $null
try {
    $temporaryConfig = New-TemporaryFile
    [System.IO.File]::WriteAllText(
        $temporaryConfig.FullName,
        (($configLines -join "`n") + "`n"),
        $utf8NoBom
    )

    foreach ($reservedPath in 'config.env', '.bundle-SHA256SUMS') {
        if (Test-Path -LiteralPath (Join-Path $bundleDirectory $reservedPath)) {
            throw "The modular deployment bundle contains reserved path: $reservedPath"
        }
    }
    $temporaryBundleRoot = Join-Path ([IO.Path]::GetTempPath()) ("vpn-modular-bundle-$([guid]::NewGuid().ToString('N'))")
    $stagedBundleDirectory = Join-Path $temporaryBundleRoot $bundleName
    [void][IO.Directory]::CreateDirectory($stagedBundleDirectory)

    $sourceBundlePrefix = "$bundleDirectory$([IO.Path]::DirectorySeparatorChar)"
    foreach ($file in Get-ChildItem -LiteralPath $bundleDirectory -Recurse -Force -File | Sort-Object FullName) {
        if (-not $file.FullName.StartsWith($sourceBundlePrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'The modular deployment bundle contains a file outside its root.'
        }
        $relativeNativePath = $file.FullName.Substring($sourceBundlePrefix.Length)
        $pathParts = $relativeNativePath.Split([IO.Path]::DirectorySeparatorChar)
        if ($file.Extension -ieq '.pyc' -or $pathParts -contains '__pycache__') {
            continue
        }
        $destination = Join-Path $stagedBundleDirectory $relativeNativePath
        [void][IO.Directory]::CreateDirectory((Split-Path -Parent $destination))
        Copy-Item -LiteralPath $file.FullName -Destination $destination
    }

    $manifestLines = [System.Collections.Generic.List[string]]::new()
    $bundlePrefix = "$stagedBundleDirectory$([IO.Path]::DirectorySeparatorChar)"
    foreach ($file in Get-ChildItem -LiteralPath $stagedBundleDirectory -Recurse -Force -File | Sort-Object FullName) {
        if (-not $file.FullName.StartsWith($bundlePrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'The modular deployment bundle contains a file outside its root.'
        }
        $relativePath = $file.FullName.Substring($bundlePrefix.Length).Replace('\', '/')
        if ($relativePath.Contains("`n") -or $relativePath.Contains("`r")) {
            throw 'The modular deployment bundle contains an unsupported file name.'
        }
        $checksum = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        $manifestLines.Add("$checksum  ./$relativePath")
    }
    $configChecksum = (Get-FileHash -LiteralPath $temporaryConfig.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $manifestLines.Add("$configChecksum  ./config.env")
    $temporaryManifest = New-TemporaryFile
    [System.IO.File]::WriteAllText(
        $temporaryManifest.FullName,
        (($manifestLines -join "`n") + "`n"),
        $utf8NoBom
    )

    $remoteCleanupRequired = $true
    Write-Host "Creating temporary deployment directory $remoteStage on $target ..."
    & ssh @sshOptions $target "mkdir -m 700 -- $remoteStage"
    if ($LASTEXITCODE -ne 0) {
        throw "Could not create remote deployment directory (exit code $LASTEXITCODE)"
    }

    Write-Host "Copying modular deployment bundle to $target ..."
    & scp @scpOptions -r $stagedBundleDirectory "${target}:$remoteStage/"
    if ($LASTEXITCODE -ne 0) {
        throw "scp failed with exit code $LASTEXITCODE"
    }

    Write-Host 'Copying component configuration ...'
    & scp @scpOptions $temporaryConfig.FullName "${target}:$remoteBundle/config.env"
    if ($LASTEXITCODE -ne 0) {
        throw "scp failed with exit code $LASTEXITCODE"
    }

    Write-Host 'Copying deployment checksum manifest ...'
    & scp @scpOptions $temporaryManifest.FullName "${target}:$remoteBundle/.bundle-SHA256SUMS"
    if ($LASTEXITCODE -ne 0) {
        throw "scp failed with exit code $LASTEXITCODE"
    }

    $remoteCommand = "set -euo pipefail; cleanup() { rm -rf -- $remoteStage; }; trap cleanup EXIT; trap 'exit 130' HUP INT TERM; cd -- $remoteBundle; chmod 600 config.env .bundle-SHA256SUMS; sha256sum -c --strict .bundle-SHA256SUMS; bash ./install-component.sh $Component ./config.env"
    Write-Host "Running modular component $Component on $target ..."
    $remoteOutput = [System.Collections.Generic.List[string]]::new()
    & ssh @sshOptions $target $remoteCommand | ForEach-Object {
        $line = [string]$_
        [void]$remoteOutput.Add($line)
        Write-Output $line
    }
    $remoteExitCode = $LASTEXITCODE
    if ($remoteExitCode -ne 0) {
        throw "Remote component failed with exit code $remoteExitCode"
    }
    if ($Component -in @('xray', 'hysteria2', 'mieru')) {
        $markerPrefix = 'VPN_ADMIN_DEPLOY_RESULT='
        $resultLines = @($remoteOutput | Where-Object { $_.StartsWith($markerPrefix, [StringComparison]::Ordinal) })
        if ($resultLines.Count -ne 1) {
            throw 'Expected exactly one deployment result marker from the server.'
        }
        try {
            $confirmedResult = $resultLines[0].Substring($markerPrefix.Length) | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            throw 'The deployment result marker contains invalid JSON.'
        }
        $resultProperties = @($confirmedResult.PSObject.Properties.Name)
        if (
            $resultProperties.Count -ne 3 -or
            $resultProperties -notcontains 'component' -or
            $resultProperties -notcontains 'protocol' -or
            $resultProperties -notcontains 'port' -or
            [string]$confirmedResult.component -ne $Component
        ) {
            throw 'The deployment result marker has an invalid structure.'
        }
        $expectedProtocol = if ($Component -eq 'hysteria2') { 'udp' } elseif ($Component -eq 'xray') { 'tcp' } else { ([string]$confirmedResult.protocol).ToLowerInvariant() }
        if (
            [string]$confirmedResult.protocol -notin @('tcp', 'udp') -or
            [string]$confirmedResult.protocol -ne $expectedProtocol -or
            ($confirmedResult.port -isnot [int] -and $confirmedResult.port -isnot [long])
        ) {
            throw 'The deployment result marker has invalid protocol or port types.'
        }
        $confirmedPort = [int]$confirmedResult.port
        if ($confirmedPort -lt 1 -or $confirmedPort -gt 65535 -or ($Component -eq 'mieru' -and $confirmedPort -lt 1025)) {
            throw 'The deployment result marker has an invalid port.'
        }
    }
}
catch {
    $operationError = $_
}
finally {
    if ($remoteCleanupRequired) {
        & ssh @sshOptions $target "rm -rf -- $remoteStage"
        if ($LASTEXITCODE -ne 0) {
            $remoteCleanupError = "Could not remove remote deployment directory $remoteStage (exit code $LASTEXITCODE)"
        }
    }
    if ($null -ne $temporaryConfig -and (Test-Path -LiteralPath $temporaryConfig.FullName -PathType Leaf)) {
        Remove-Item -LiteralPath $temporaryConfig.FullName -Force
    }
    if ($null -ne $temporaryManifest -and (Test-Path -LiteralPath $temporaryManifest.FullName -PathType Leaf)) {
        Remove-Item -LiteralPath $temporaryManifest.FullName -Force
    }
    if ($null -ne $temporaryBundleRoot -and (Test-Path -LiteralPath $temporaryBundleRoot -PathType Container)) {
        $resolvedTemporaryRoot = [IO.Path]::GetFullPath($temporaryBundleRoot)
        $temporaryDirectoryPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
        if (
            -not $resolvedTemporaryRoot.StartsWith($temporaryDirectoryPrefix, [StringComparison]::OrdinalIgnoreCase) -or
            (Split-Path -Leaf $resolvedTemporaryRoot) -notmatch '^vpn-modular-bundle-[0-9a-f]{32}$'
        ) {
            throw "Refusing to remove unexpected temporary bundle directory: $resolvedTemporaryRoot"
        }
        Remove-Item -LiteralPath $resolvedTemporaryRoot -Recurse -Force
    }
}

if ($null -ne $operationError) {
    if ($null -ne $remoteCleanupError) {
        throw "$($operationError.Exception.Message) Remote cleanup also failed: $remoteCleanupError"
    }
    throw $operationError
}
if ($null -ne $remoteCleanupError) {
    throw $remoteCleanupError
}

Write-Host "Modular component $Component completed on $target."
