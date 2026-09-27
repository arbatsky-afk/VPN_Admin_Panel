Set-StrictMode -Version Latest

function Get-PanelSettingsPath {
    param(
        [Parameter(Mandatory)]
        [string]$ProjectRoot
    )

    return Join-Path $ProjectRoot 'runtime\panel\settings.json'
}

function Get-PrimarySshPrivateKey {
    param(
        [Parameter(Mandatory)]
        [string]$ProjectRoot
    )

    $keyRecords = @(Get-ConfiguredSshKeyRecords -ProjectRoot $ProjectRoot)
    return [string]($keyRecords | Where-Object { $_.IsPrimary } | Select-Object -First 1).PrivateKeyPath
}

function Get-SshFixPrivateKeys {
    param(
        [Parameter(Mandatory)]
        [string]$ProjectRoot
    )

    $seenPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($keyRecord in @(Get-ConfiguredSshKeyRecords -ProjectRoot $ProjectRoot)) {
        $privateKeyPath = [string]$keyRecord.PrivateKeyPath
        if ($seenPaths.Add($privateKeyPath)) {
            $privateKeyPath
        }
    }
}

function Get-ConfiguredSshPort {
    param(
        [Parameter(Mandatory)]
        [string]$ProjectRoot
    )

    $settings = Get-PanelSshSettings -ProjectRoot $ProjectRoot
    $portProperty = $settings.ssh.PSObject.Properties['port']
    if (
        $null -eq $portProperty -or
        ($portProperty.Value -isnot [int] -and $portProperty.Value -isnot [long])
    ) {
        throw 'Panel settings must contain an integer ssh.port.'
    }
    if ($portProperty.Value -lt 1 -or $portProperty.Value -gt 65535) {
        throw 'Panel settings ssh.port must be between 1 and 65535.'
    }
    $port = [int]$portProperty.Value
    return $port
}

function Get-ConfiguredSshKeyRecords {
    param(
        [Parameter(Mandatory)]
        [string]$ProjectRoot
    )

    $settings = Get-PanelSshSettings -ProjectRoot $ProjectRoot
    $sshSettings = $settings.ssh
    $keysProperty = $sshSettings.PSObject.Properties['keys']
    if ($null -eq $keysProperty) {
        return Get-LegacySshKeyRecords -SshSettings $sshSettings
    }
    return Get-ListSshKeyRecords -ConfiguredKeys $keysProperty.Value
}

function Get-ListSshKeyRecords {
    param(
        [Parameter(Mandatory)]
        [object]$ConfiguredKeys
    )

    if ($ConfiguredKeys -is [string] -or $ConfiguredKeys -isnot [System.Collections.IEnumerable]) {
        throw 'Local configuration must contain a non-empty ssh.keys list.'
    }
    $configuredEntries = @($ConfiguredKeys)
    if ($configuredEntries.Count -eq 0) {
        throw 'Local configuration must contain a non-empty ssh.keys list.'
    }
    $keyRecords = [System.Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt $configuredEntries.Count; $index++) {
        $entry = $configuredEntries[$index]
        if ($null -eq $entry -or $entry -isnot [PSCustomObject]) {
            throw "Local configuration has an invalid ssh.keys[$index] entry."
        }
        $nameProperty = $entry.PSObject.Properties['name']
        $primaryProperty = $entry.PSObject.Properties['is_primary']
        $pathProperty = $entry.PSObject.Properties['private_key_path']
        $name = if ($null -eq $nameProperty) { $null } else { [string]$nameProperty.Value }
        if ([string]::IsNullOrWhiteSpace($name)) {
            throw "Local configuration has an invalid ssh.keys[$index].name."
        }
        if ($null -eq $primaryProperty -or $primaryProperty.Value -isnot [bool]) {
            throw "Local configuration has an invalid ssh.keys[$index].is_primary."
        }
        $configuredPath = if ($null -eq $pathProperty) { $null } else { [string]$pathProperty.Value }
        if ([string]::IsNullOrWhiteSpace($configuredPath)) {
            throw "Local configuration has an invalid ssh.keys[$index].private_key_path."
        }
        $privateKeyPath = Get-ExistingSshPrivateKey -ConfiguredPath $configuredPath -DisplayName "ssh.keys[$index].private_key_path"
        [void]$keyRecords.Add([PSCustomObject]@{
            Name = $name.Trim()
            PrivateKeyPath = $privateKeyPath
            IsPrimary = [bool]$primaryProperty.Value
        })
    }
    Assert-OnePrimarySshKey -KeyRecords $keyRecords
    return $keyRecords
}

function Get-LegacySshKeyRecords {
    param(
        [Parameter(Mandatory)]
        [object]$SshSettings
    )

    $primaryKey = Get-ConfiguredSshPrivateKey -SshSettings $SshSettings -PropertyName 'private_key_path' -Required
    $keyRecords = [System.Collections.Generic.List[object]]::new()
    [void]$keyRecords.Add([PSCustomObject]@{ Name = 'Primary'; PrivateKeyPath = $primaryKey; IsPrimary = $true })
    $optionalKey = Get-ConfiguredSshPrivateKey -SshSettings $SshSettings -PropertyName 'amnezia_private_key_path'
    if ($null -ne $optionalKey -and $optionalKey -ne $primaryKey) {
        [void]$keyRecords.Add([PSCustomObject]@{ Name = 'Amnezia'; PrivateKeyPath = $optionalKey; IsPrimary = $false })
    }
    return $keyRecords
}

function Assert-OnePrimarySshKey {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IEnumerable]$KeyRecords
    )

    if (@($KeyRecords | Where-Object { $_.IsPrimary }).Count -ne 1) {
        throw 'Local configuration must mark exactly one ssh.keys entry as primary.'
    }
}

function Get-PanelSshSettings {
    param(
        [Parameter(Mandatory)]
        [string]$ProjectRoot
    )

    $configPath = Get-PanelSettingsPath -ProjectRoot $ProjectRoot
    if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
        throw "Panel settings are missing: $configPath. Configure SSH in Admin Panel Settings."
    }
    try {
        $settings = Get-Content -LiteralPath $configPath -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Panel settings contain invalid JSON: $configPath"
    }
    $sshProperty = $settings.PSObject.Properties['ssh']
    if ($null -eq $sshProperty -or $null -eq $sshProperty.Value) {
        throw "Panel settings are missing ssh: $configPath"
    }
    return $settings
}

function Get-ConfiguredSshPrivateKey {
    param(
        [Parameter(Mandatory)]
        [object]$SshSettings,

        [Parameter(Mandatory)]
        [string]$PropertyName,

        [switch]$Required
    )

    $property = $SshSettings.PSObject.Properties[$PropertyName]
    $configuredPath = if ($null -eq $property) { $null } else { [string]$property.Value }
    if ([string]::IsNullOrWhiteSpace($configuredPath)) {
        if ($Required) {
            throw "Local configuration is missing ssh.$PropertyName."
        }
        return $null
    }
    return Get-ExistingSshPrivateKey -ConfiguredPath $configuredPath -DisplayName "ssh.$PropertyName"
}

function Get-ExistingSshPrivateKey {
    param(
        [Parameter(Mandatory)]
        [string]$ConfiguredPath,

        [Parameter(Mandatory)]
        [string]$DisplayName
    )

    if (-not (Test-Path -LiteralPath $ConfiguredPath -PathType Leaf)) {
        throw "The SSH private key configured by $DisplayName could not be found."
    }
    return $ConfiguredPath
}

Export-ModuleMember -Function Get-PanelSettingsPath, Get-PrimarySshPrivateKey, Get-SshFixPrivateKeys, Get-ConfiguredSshPort
