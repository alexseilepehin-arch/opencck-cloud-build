param([string]$ArtifactRoot=(Join-Path (Split-Path -Parent $PSScriptRoot) 'cloud-artifacts'))
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'CloudPolicyV2Publisher.Common.psm1') -Force -DisableNameChecking
# Read existing v1 output as data. No RSC is executed and no DNS is repeated.
function Read-Manifest([string]$Path) {
 $m=@{};foreach($l in ([IO.File]::ReadAllText($Path)-split '[;\r\n]+'|Where-Object{$_})){if($l-cnotmatch '^([a-z0-9_]+)=(.+)$'-or$m.ContainsKey($Matches[1])){throw 'V1_MANIFEST_SCHEMA'};$m[$Matches[1]]=$Matches[2]};return $m
}
function Read-CheckedPayload([string]$Leaf,[string]$Size,[string]$Hash) {
 if($Leaf-cnotmatch '^(force-update|full-policy-[0-9]{3})[.]rsc$'-or$Size-cnotmatch '^[0-9]+$'-or$Hash-cnotmatch '^[a-f0-9]{64}$'){throw 'V1_PAYLOAD_DESCRIPTOR'}
 $p=Join-Path $ArtifactRoot $Leaf
 if((Get-Item -LiteralPath $p).Length-ne[long]$Size-or(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()-cne$Hash){throw 'V1_PAYLOAD_HASH_OR_SIZE'}
 return [IO.File]::ReadAllText($p)
}
$force=Read-Manifest (Join-Path $ArtifactRoot 'force-manifest.txt')
$full=Read-Manifest (Join-Path $ArtifactRoot 'full-policy-manifest.txt')
if($force.version-cne'1'-or$full.version-cne'1'-or$force.kind-cne'force'-or$full.kind-cne'full'-or$force.build_id-cne$full.build_id-or$force.build_id-cnotmatch'^[0-9]{14}$'){throw 'V1_PAIRED_BUILD_REQUIRED'}
$f=Read-CheckedPayload $force.file $force.size_bytes $force.sha256
$forceIps=@([regex]::Matches($f,'(?m)^/ip/firewall/address-list/add list=\$AwgCloudForceTargetSlot address=([0-9./]+) timeout=[0-9a-z]+ comment="awg-force-cloud-[0-9]+"\r?$')|ForEach-Object{$_.Groups[1].Value})
$metaIps=@([regex]::Matches($f,'(?m)^/ip/firewall/address-list/add list=awg_meta_quic_ip4 address=([0-9.]+) timeout=[0-9a-z]+ comment="awg-meta-quic-cloud-[0-9]+"\r?$')|ForEach-Object{$_.Groups[1].Value})
if($forceIps.Count-ne[int]$force.expected_count-or$metaIps.Count-ne[int]$force.meta_quic_count){throw 'V1_FORCE_OR_META_ROWS'}
# Meta and bootstrap DNS can legitimately differ between lookups. A QUIC allow
# must always be backed by VPN routing; include the same Meta IPs in v2 force.
# Legacy artifacts remain byte-for-byte unchanged.
$forceIps=@($forceIps+$metaIps|Sort-Object -Unique)
$fullIps=New-Object 'Collections.Generic.List[string]'
for($n=1;$n-le[int]$full.chunk_count;$n++){
 $s=$n.ToString('D3');$b=Read-CheckedPayload $full["chunk_${s}_file"] $full["chunk_${s}_size"] $full["chunk_${s}_sha256"]
 foreach($m in [regex]::Matches($b,'(?m)^/ip/firewall/address-list/add list=\$AwgCloudFullTargetSlot address=([0-9./]+) timeout=[0-9a-z]+ comment=opencck\r?$')){$fullIps.Add($m.Groups[1].Value)}
}
if($fullIps.Count-ne[int]$full.expected_count){throw 'V1_FULL_ROWS'}
$created=[DateTimeOffset]::ParseExact($full.created_at_utc,'yyyy-MM-ddTHH:mm:ssZ',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal).ToUnixTimeSeconds()
$publication=New-CloudPolicyV2Publication -BuildId $full.build_id -ForceIps $forceIps -MetaQuicIps $metaIps -FullIps $fullIps.ToArray() -CreatedEpoch $created
Write-CloudPolicyV2Publication -Publication $publication -OutputRoot $ArtifactRoot
