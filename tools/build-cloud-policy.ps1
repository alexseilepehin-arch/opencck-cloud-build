param(
    [ValidateSet('all', 'force', 'full')]
    [string]$Kind = 'all',
    [string]$SettingsPath = (Join-Path (Split-Path -Parent $PSScriptRoot) '_settings.bat'),
    [string]$OutDir = (Join-Path (Split-Path -Parent $PSScriptRoot) 'cloud-artifacts'),
    [string]$CacheDir = (Join-Path (Split-Path -Parent $PSScriptRoot) 'opencck-generated')
)

$ErrorActionPreference = 'Stop'

function Split-Values([string]$value) {
    @($value -split '[,; ]+' | Where-Object { $_ -and $_.Trim() } | ForEach-Object { $_.Trim() })
}

function Read-BatSettings([string]$Path) {
    $map = @{}
    foreach ($line in (Get-Content -LiteralPath $Path)) {
        $text = $line.Trim()
        if ($text -match '^set\s+"([^=]+)=(.*)"\s*$') {
            $map[$Matches[1]] = $Matches[2]
        } elseif ($text -match '^set\s+([^=]+)=(.*)\s*$') {
            $map[$Matches[1]] = $Matches[2]
        }
    }

    $changed = $true
    while ($changed) {
        $changed = $false
        foreach ($key in @($map.Keys)) {
            $value = $map[$key]
            $expanded = [regex]::Replace($value, '%([^%]+)%', {
                param($m)
                $name = $m.Groups[1].Value
                if ($map.ContainsKey($name)) { return $map[$name] }
                return $m.Value
            })
            if ($expanded -ne $value) {
                $map[$key] = $expanded
                $changed = $true
            }
        }
    }
    $map
}

function Assert-IPv4([string]$ip) {
    if (-not $ip) { return $false }
    if ($ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { return $false }
    foreach ($part in $ip.Split('.')) {
        $n = [int]$part
        if ($n -lt 0 -or $n -gt 255) { return $false }
    }
    return $true
}

function Assert-IPv4OrCidr([string]$value) {
    $text = $value.Trim()
    if ($text -match '^(?<ip>\d{1,3}(\.\d{1,3}){3})/(?<prefix>\d{1,2})$') {
        $prefix = [int]$Matches['prefix']
        return (Assert-IPv4 $Matches['ip']) -and $prefix -ge 0 -and $prefix -le 32
    }
    return Assert-IPv4 $text
}

function Add-UniqueIPv4 {
    param([hashtable]$Map, [string]$Ip)
    $value = $Ip.Trim()
    if ((Assert-IPv4 $value) -and -not $Map.ContainsKey($value)) {
        $Map[$value] = $true
    }
}

function Add-UniqueIPv4OrCidr {
    param([hashtable]$Map, [string]$Value)
    $text = $Value.Trim()
    if ((Assert-IPv4OrCidr $text) -and -not $Map.ContainsKey($text)) {
        $Map[$text] = $true
    }
}

function Resolve-TargetDomainIps([string[]]$Domains) {
    $map = @{}
    foreach ($domain in $Domains) {
        if ($domain -notmatch '^[A-Za-z0-9_.-]+$') { continue }
        Write-Host "Resolving bootstrap domain: $domain"
        try {
            $records = Resolve-DnsName -Name $domain -Type A -ErrorAction Stop
            foreach ($record in $records) {
                if ($record.IPAddress) { Add-UniqueIPv4 -Map $map -Ip $record.IPAddress }
            }
        } catch {
            Write-Warning "DNS resolve failed for ${domain}: $($_.Exception.Message)"
        }
    }
    @($map.Keys | Sort-Object)
}

function New-OpenCckMap {
    param([string[]]$Groups)

    $map = @{}
    foreach ($group in $Groups) {
        $encoded = [uri]::EscapeDataString($group)
        $url = "https://iplist.opencck.org/?format=text&group=$encoded&data=ip4"
        Write-Host "Downloading OpenCCK group: $group"
        $content = $null
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            try {
                $content = (Invoke-WebRequest -UseBasicParsing -Uri $url -TimeoutSec 180).Content
                break
            } catch {
                Write-Warning "OpenCCK group '$group' download failed, attempt ${attempt}/3: $($_.Exception.Message)"
                if ($attempt -lt 3) { Start-Sleep -Seconds (5 * $attempt) }
            }
        }
        if (-not $content) {
            throw "OPENCCK_DOWNLOAD_FAILED group=$group"
        }
        foreach ($line in ($content -split "\r?\n")) {
            Add-UniqueIPv4 -Map $map -Ip $line
        }
    }
    $map
}

function New-CloudOomGuardLines {
    param(
        [string]$Kind,
        [int]$AddedCount,
        [hashtable]$Settings
    )
    $limit = $Settings['OPENCCK_MIN_FREE_BYTES']
    if (-not $limit) { $limit = '367001600' }
    @(
        ":if ([/system/resource/get free-memory] < $limit) do={",
        "  :log error `"AWG_CLOUD_OOM_GUARD kind=$Kind count=$AddedCount`"",
        "  :do { /file/set [find where name=`"$($Settings['OPENCCK_STATUS_FILE'])`"] contents=`"CLOUD_OOM_GUARD kind=$Kind count=$AddedCount`" } on-error={}",
        "  :if (`"$Kind`" = `"full`") do={ :do { /ip/firewall/address-list/remove [find where list=`$AwgCloudFullTargetSlot] } on-error={} }",
        "  :if (`"$Kind`" = `"force`") do={ :do { /ip/firewall/address-list/remove [find where list=`$AwgCloudForceTargetSlot] } on-error={} }",
        "  :global AwgCloudUpdateRunning",
        "  :set AwgCloudUpdateRunning false",
        "  :error `"AWG_CLOUD_OOM_GUARD`"",
        "}"
    )
}

function Write-Manifest {
    param([string]$Path, [hashtable]$Fields)
    $parts = foreach ($key in $Fields.Keys) { "$key=$($Fields[$key])" }
    [System.IO.File]::WriteAllText($Path, (($parts -join ';') + ';'), [System.Text.UTF8Encoding]::new($false))
}

function Get-Sha256([string]$Path) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $stream = [System.IO.File]::OpenRead($Path)
        try {
            $hash = $sha.ComputeHash($stream)
            -join ($hash | ForEach-Object { $_.ToString('x2') })
        } finally {
            $stream.Dispose()
        }
    } finally {
        $sha.Dispose()
    }
}

function Write-ForcePayload {
    param(
        [string[]]$ForceIps,
        [hashtable]$Settings,
        [string]$BuildId,
        [string]$OutDir
    )
    $timeout = $Settings['FORCE_ENTRY_TIMEOUT']
    if (-not $timeout) { $timeout = '2d' }
    $file = Join-Path $OutDir 'force-update.rsc'
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add(":global AwgCloudForceTargetSlot")
    $lines.Add(":global AwgCloudPayloadComplete")
    $lines.Add(":set AwgCloudPayloadComplete `"`"")
    $lines.Add(":log info `"AWG_CLOUD_FORCE_PAYLOAD_START build=$BuildId count=$($ForceIps.Count)`"")
    $added = 0
    foreach ($ip in $ForceIps) {
        $lines.Add("/ip/firewall/address-list/add list=`$AwgCloudForceTargetSlot address=$ip timeout=$timeout comment=`"awg-force-cloud-$BuildId`"")
        $added++
        if (($added % 500) -eq 0) {
            foreach ($guardLine in (New-CloudOomGuardLines -Kind force -AddedCount $added -Settings $Settings)) {
                $lines.Add($guardLine)
            }
        }
    }
    foreach ($guardLine in (New-CloudOomGuardLines -Kind force -AddedCount $added -Settings $Settings)) {
        $lines.Add($guardLine)
    }
    $lines.Add(":set AwgCloudPayloadComplete `"force:${BuildId}:$added`"")
    $lines.Add(":log info `"AWG_CLOUD_FORCE_PAYLOAD_COMPLETE build=$BuildId count=$added`"")
    [System.IO.File]::WriteAllLines($file, $lines, [System.Text.UTF8Encoding]::new($false))

    [ordered]@{
        version = '1'
        kind = 'force'
        build_id = $BuildId
        file = 'force-update.rsc'
        size_bytes = (Get-Item -LiteralPath $file).Length
        expected_count = $ForceIps.Count
        min_size = 100
        created_at_utc = (Get-Date).ToUniversalTime().ToString('s') + 'Z'
        sha256 = Get-Sha256 $file
    }
}

function Write-FullPayloadChunks {
    param(
        [string[]]$OpenCckIps,
        [hashtable]$Settings,
        [string]$BuildId,
        [string]$OutDir
    )
    $chunkSize = 5000
    if ($Settings['CLOUD_FULL_CHUNK_SIZE'] -match '^\d+$') { $chunkSize = [int]$Settings['CLOUD_FULL_CHUNK_SIZE'] }
    if ($chunkSize -lt 1000) { $chunkSize = 5000 }
    $timeout = $Settings['OPENCCK_ENTRY_TIMEOUT']
    if (-not $timeout) { $timeout = '7d' }
    $chunkCount = [Math]::Ceiling($OpenCckIps.Count / $chunkSize)
    $manifest = [ordered]@{
        version = '1'
        kind = 'full'
        build_id = $BuildId
        chunk_count = $chunkCount
        expected_count = $OpenCckIps.Count
        min_size = 100
        created_at_utc = (Get-Date).ToUniversalTime().ToString('s') + 'Z'
    }

    for ($chunk = 1; $chunk -le $chunkCount; $chunk++) {
        $suffix = '{0:D3}' -f $chunk
        $fileName = "full-policy-$suffix.rsc"
        $file = Join-Path $OutDir $fileName
        $start = ($chunk - 1) * $chunkSize
        $end = [Math]::Min($start + $chunkSize - 1, $OpenCckIps.Count - 1)
        $ips = @($OpenCckIps[$start..$end])
        $lines = [System.Collections.Generic.List[string]]::new()
        $lines.Add(":global AwgCloudFullTargetSlot")
        $lines.Add(":global AwgCloudChunkMarker")
        $lines.Add(":set AwgCloudChunkMarker `"`"")
        $lines.Add(":log info `"AWG_CLOUD_FULL_CHUNK_START build=$BuildId chunk=$suffix count=$($ips.Count)`"")
        $added = 0
        foreach ($ip in $ips) {
            $lines.Add("/ip/firewall/address-list/add list=`$AwgCloudFullTargetSlot address=$ip timeout=$timeout comment=opencck")
            $added++
            if (($added % 1000) -eq 0) {
                foreach ($guardLine in (New-CloudOomGuardLines -Kind full -AddedCount ($start + $added) -Settings $Settings)) {
                    $lines.Add($guardLine)
                }
            }
        }
        foreach ($guardLine in (New-CloudOomGuardLines -Kind full -AddedCount ($start + $added) -Settings $Settings)) {
            $lines.Add($guardLine)
        }
        $lines.Add(":set AwgCloudChunkMarker `"full:${BuildId}:$suffix`"")
        $lines.Add(":log info `"AWG_CLOUD_FULL_CHUNK_COMPLETE build=$BuildId chunk=$suffix count=$($ips.Count)`"")
        [System.IO.File]::WriteAllLines($file, $lines, [System.Text.UTF8Encoding]::new($false))
        $manifest["chunk_${suffix}_file"] = $fileName
        $manifest["chunk_${suffix}_size"] = (Get-Item -LiteralPath $file).Length
        $manifest["chunk_${suffix}_sha256"] = Get-Sha256 $file
    }
    $manifest
}

$settings = Read-BatSettings -Path $SettingsPath
New-Item -ItemType Directory -Force -Path $OutDir, $CacheDir | Out-Null
if ($Kind -eq 'all') {
    Get-ChildItem -LiteralPath $OutDir -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
} elseif ($Kind -eq 'force') {
    Get-ChildItem -LiteralPath $OutDir -File -Filter 'force-*' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
} elseif ($Kind -eq 'full') {
    Get-ChildItem -LiteralPath $OutDir -File -Filter 'full-policy-*' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
}

$buildId = (Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss')

if ($settings['FORCE_ENTRY_TIMEOUT'] -ne '2d') {
    Write-Warning "FORCE_ENTRY_TIMEOUT is '$($settings['FORCE_ENTRY_TIMEOUT'])'. Cloud production default should be 2d."
}

if ($Kind -in @('all', 'force')) {
    $targetDomains = Split-Values $settings['TARGET_DOMAINS']
    $forceMap = @{}
    foreach ($ip in (Resolve-TargetDomainIps -Domains $targetDomains)) { Add-UniqueIPv4 -Map $forceMap -Ip $ip }
    foreach ($range in (Split-Values $settings['TELEGRAM_FORCE_RANGES'])) { Add-UniqueIPv4OrCidr -Map $forceMap -Value $range }
    foreach ($badIp in (Split-Values $settings['META_BAD_DNS_SEEDS'])) {
        if ($forceMap.ContainsKey($badIp)) { $forceMap.Remove($badIp) }
    }
    $forceIps = @($forceMap.Keys | Sort-Object)
    if ($forceIps.Count -lt 50) { throw "Cloud force list too small: $($forceIps.Count)" }
    $forceManifest = Write-ForcePayload -ForceIps $forceIps -Settings $settings -BuildId $buildId -OutDir $OutDir
    Write-Manifest -Path (Join-Path $OutDir 'force-manifest.txt') -Fields $forceManifest
    Write-Host "Force artifact: count=$($forceIps.Count)"
}

if ($Kind -in @('all', 'full')) {
    $groups = Split-Values $settings['OPENCCK_DEFAULT_GROUPS']
    if ($settings['INCLUDE_HEAVY_GROUPS_IN_DEFAULT'] -eq '1') {
        $groups += Split-Values $settings['OPENCCK_HEAVY_GROUPS']
    }
    $groups = @($groups | Select-Object -Unique)
    $cacheFile = Join-Path $CacheDir 'opencck-ip4-cache.txt'
    try {
        $map = New-OpenCckMap -Groups $groups
        $cacheIps = @($map.Keys | Sort-Object)
        if ($cacheIps.Count -gt 0) {
            [System.IO.File]::WriteAllLines($cacheFile, $cacheIps, [System.Text.UTF8Encoding]::new($false))
        }
    } catch {
        Write-Warning "OpenCCK live download failed: $($_.Exception.Message)"
        if (-not (Test-Path -LiteralPath $cacheFile)) { throw }
        $map = @{}
        foreach ($line in (Get-Content -LiteralPath $cacheFile)) { Add-UniqueIPv4 -Map $map -Ip $line }
    }
    $openCckIps = @($map.Keys | Sort-Object)
    if ($openCckIps.Count -lt 30000) { throw "Cloud OpenCCK list too small: $($openCckIps.Count)" }
    $fullManifest = Write-FullPayloadChunks -OpenCckIps $openCckIps -Settings $settings -BuildId $buildId -OutDir $OutDir
    Write-Manifest -Path (Join-Path $OutDir 'full-policy-manifest.txt') -Fields $fullManifest
    Write-Host "Full artifacts: count=$($openCckIps.Count), chunks=$($fullManifest['chunk_count'])"
}

Get-ChildItem -LiteralPath $OutDir | Sort-Object Name | Select-Object Name, Length
