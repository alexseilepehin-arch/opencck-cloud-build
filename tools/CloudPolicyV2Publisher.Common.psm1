Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ExactIpv4Collapse.Common.psm1') -Force -DisableNameChecking
# Pure data publisher. It never resolves names, downloads inputs, executes RSC,
# publishes GitHub content, or writes the existing v1 root artifacts.
function Get-Cpv2Hash([string]$Text){$s=[Security.Cryptography.SHA512]::Create();try{([BitConverter]::ToString($s.ComputeHash([Text.Encoding]::ASCII.GetBytes($Text)))).Replace('-','').ToLowerInvariant()}finally{$s.Dispose()}}
function ConvertTo-Cpv2Range([string]$Value){
 if($Value-cnotmatch'^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})(/(0|[1-9]|[12][0-9]|3[0-2]))?$'){throw 'CPV2_IPV4_OR_CIDR_REQUIRED'}
 $parts=$Value.Split('/');[uint64]$number=0;foreach($o in $parts[0].Split('.')){if([int]$o-gt255){throw 'CPV2_IPV4_OCTET'};$number=$number*256+[int]$o};$prefix=32;if($parts.Length-eq2){$prefix=[int]$parts[1]};[uint64]$size=[Math]::Pow(2,32-$prefix);[uint64]$low=$number-($number%$size)
 [pscustomobject]@{Start=$low;End=($low+$size-1);Address=$number;Prefix=$prefix}
}
function ConvertTo-Cpv2Manifest([Collections.IDictionary]$Fields){($Fields.Keys|ForEach-Object{$_+'='+$Fields[$_]})-join"`n"}
function Read-Cpv2Manifest([string]$Text){
 if($Text.Length-eq0-or$Text.Length-ge60000-or$Text.Contains("`r")){throw 'CPV2_MANIFEST_BYTES'};$map=@{}
 foreach($line in $Text.Split("`n")){if($line-cnotmatch'^([a-z0-9_]+)=([A-Za-z0-9._-]+)$'-or$map.ContainsKey($Matches[1])){throw 'CPV2_MANIFEST_SCHEMA'};$map[$Matches[1]]=$Matches[2]};return $map
}
function New-CloudPolicyV2Publication {
 [CmdletBinding()]param([Parameter(Mandatory)][string]$BuildId,[Parameter(Mandatory)][string[]]$ForceIps,[Parameter(Mandatory)][AllowEmptyCollection()][string[]]$MetaQuicIps,[Parameter(Mandatory)][string[]]$FullIps,[Parameter(Mandatory)][long]$CreatedEpoch)
 if($BuildId-cnotmatch'^[1-9][0-9]{0,19}$'-or$CreatedEpoch-lt0-or$CreatedEpoch-gt253402300799){throw 'CPV2_BUILD_OR_EPOCH'}
 if($ForceIps.Count-lt1-or$ForceIps.Count-gt2500-or$FullIps.Count-lt1-or$FullIps.Count-gt250000-or$MetaQuicIps.Count-gt2500){throw 'CPV2_COUNT_BOUNDS'}
 $exact=New-Object 'Collections.Generic.HashSet[UInt64]';$ranges=New-Object 'Collections.Generic.List[object]'
 foreach($lane in @($ForceIps,$FullIps)){$seen=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal);foreach($ip in $lane){if(-not$seen.Add($ip)){throw 'CPV2_DUPLICATE_INPUT'};$r=ConvertTo-Cpv2Range $ip;if($r.Prefix-eq32){[void]$exact.Add($r.Address)}else{$ranges.Add($r)}}}
 $metaSeen=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
 foreach($ip in $MetaQuicIps){if($ip.Contains('/')-or-not$metaSeen.Add($ip)){throw 'CPV2_META_IPV4_UNIQUE_REQUIRED'};$r=ConvertTo-Cpv2Range $ip;$covered=$exact.Contains($r.Address);if(-not$covered){foreach($range in $ranges){if($r.Address-ge$range.Start-and$r.Address-le$range.End){$covered=$true;break}}};if(-not$covered){throw 'CPV2_META_NOT_COVERED_BY_EXISTING_VPN_POLICY'}}
 # FULL ONLY: validate the exact union independently before any publication bytes.
 # Force/Meta and legacy v1 artifacts keep their original bytes and membership.
 $fullInputCount=$FullIps.Count
 $compaction=Get-ExactIpv4Collapse -Values $FullIps
 $FullIps=[string[]]$compaction.Values
 $files=[ordered]@{};$force=$ForceIps-join"`n";$files['v2/force-policy.txt']=$force
 if($force.Length-ge60000){throw 'CPV2_FORCE_FILE_TOO_LARGE'}
 $forceFields=[ordered]@{version='2';kind='force';build_id=$BuildId;file='force-policy.txt';size_bytes=$force.Length;expected_count=$ForceIps.Count;sha512=(Get-Cpv2Hash $force);created_epoch=$CreatedEpoch}
 $fm=ConvertTo-Cpv2Manifest $forceFields;$files['v2/force-manifest.txt']=$fm;$forceHash=Get-Cpv2Hash $fm;$generation=(Get-Cpv2Hash ("force`n"+$fm)).Substring(0,16)
 $chunks=[int][Math]::Ceiling($FullIps.Count/2000.0);$fullFields=[ordered]@{version='2';kind='full';build_id=$BuildId;chunk_count=$chunks;expected_count=$FullIps.Count;created_epoch=$CreatedEpoch}
 for($n=1;$n-le$chunks;$n++){$suffix=$n.ToString('D3');$leaf='full-policy-'+$suffix+'.txt';$first=($n-1)*2000;$last=[Math]::Min($first+1999,$FullIps.Count-1);$blob=$FullIps[$first..$last]-join"`n";if($blob.Length-ge60000){throw 'CPV2_CHUNK_TOO_LARGE'};$files['v2/'+$leaf]=$blob;$fullFields['chunk_'+$suffix+'_file']=$leaf;$fullFields['chunk_'+$suffix+'_size']=$blob.Length;$fullFields['chunk_'+$suffix+'_count']=$last-$first+1;$fullFields['chunk_'+$suffix+'_sha512']=Get-Cpv2Hash $blob}
 $files['v2/full-policy-manifest.txt']=ConvertTo-Cpv2Manifest $fullFields
 $meta=$MetaQuicIps-join"`n";if($meta.Length-ge60000){throw 'CPV2_META_FILE_TOO_LARGE'};$base='v2/meta/'+$generation+'/'
 $sidecar=[ordered]@{SchemaVersion=1;Kind='meta-quic';BuildId=$BuildId;CreatedEpoch=$CreatedEpoch;ForceGeneration=$generation;ForceManifestSHA512=$forceHash;File='meta-quic.txt';SizeBytes=$meta.Length;Count=$MetaQuicIps.Count;TTLSeconds=172800;SHA512=(Get-Cpv2Hash $meta)}|ConvertTo-Json -Compress
 $files[$base+'meta-quic.txt']=$meta;$files[$base+'manifest.json']=$sidecar;$files[$base+'manifest.seal.json']=([ordered]@{SchemaVersion=1;ForceGeneration=$generation;ManifestSHA512=(Get-Cpv2Hash $sidecar)}|ConvertTo-Json -Compress)
 $inventory=@();foreach($path in $files.Keys){$inventory+=@([pscustomobject]@{Path=$path;Bytes=$files[$path].Length;SHA512=(Get-Cpv2Hash $files[$path])})}
 [pscustomobject]@{SchemaVersion=1;BuildId=$BuildId;CreatedEpoch=$CreatedEpoch;Files=$files;Inventory=$inventory;ForceGeneration=$generation;ForceManifestSHA512=$forceHash;MetaVpnCoverageProved=$true;MetaCount=$MetaQuicIps.Count;ForceCount=$ForceIps.Count;FullCount=$FullIps.Count;FullInputCount=$fullInputCount;FullAddressCount=$compaction.Proof.AddressCount;FullCoverageProof=$compaction.Proof;ChunkSize=2000;V1Changed=$false;Published=$false;CanApply=$false}
}
function Test-CloudPolicyV2Publication {
 [CmdletBinding()]param([Parameter(Mandatory)]$Publication)
 if($Publication.Files-isnot[Collections.IDictionary]){throw 'CPV2_FILES_REQUIRED'};$files=$Publication.Files
 $fm=Read-Cpv2Manifest ([string]$files['v2/force-manifest.txt']);$full=Read-Cpv2Manifest ([string]$files['v2/full-policy-manifest.txt'])
 if($fm.Count-ne8-or$fm.version-cne'2'-or$fm.kind-cne'force'-or$fm.file-cne'force-policy.txt'-or$full.version-cne'2'-or$full.kind-cne'full'-or$fm.build_id-cne$full.build_id-or$fm.created_epoch-cne$full.created_epoch-or$full.chunk_count-cnotmatch'^[1-9][0-9]{0,2}$'-or[int]$full.chunk_count-gt125){throw 'CPV2_PAIRED_MANIFEST_SCHEMA'}
 $all=New-Object 'Collections.Generic.List[string]';for($n=1;$n-le[int]$full.chunk_count;$n++){$leaf='full-policy-'+$n.ToString('D3')+'.txt';foreach($ip in ([string]$files['v2/'+$leaf]).Split("`n")){$all.Add($ip)}}
 $gen=(Get-Cpv2Hash ("force`n"+[string]$files['v2/force-manifest.txt'])).Substring(0,16);$metaBlob=[string]$files['v2/meta/'+$gen+'/meta-quic.txt'];$meta=@();if($metaBlob.Length){$meta=@($metaBlob.Split("`n"))}
 $expected=New-CloudPolicyV2Publication -BuildId $fm.build_id -CreatedEpoch ([long]$fm.created_epoch) -ForceIps @(([string]$files['v2/force-policy.txt']).Split("`n")) -FullIps $all.ToArray() -MetaQuicIps $meta
 if($files.Count-ne$expected.Files.Count){throw 'CPV2_FILE_SET'};foreach($path in $expected.Files.Keys){if(-not$files.Contains($path)-or[string]$files[$path]-cne$expected.Files[$path]){throw 'CPV2_CONTENT_OR_MANIFEST_MISMATCH'}}
 return $true
}
function Write-CloudPolicyV2Publication {
 [CmdletBinding()]param([Parameter(Mandatory)]$Publication,[Parameter(Mandatory)][string]$OutputRoot)
 [void](Test-CloudPolicyV2Publication $Publication);$root=[IO.Path]::GetFullPath($OutputRoot).TrimEnd('\');if(-not[IO.Directory]::Exists($root)){throw 'CPV2_EXISTING_OUTPUT_ROOT_REQUIRED'}
 if((Get-Item -LiteralPath $root).Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'CPV2_REPARSE_POINT'}
 $v1=@{};foreach($f in Get-ChildItem -LiteralPath $root -File){$v1[$f.FullName]=(Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash}
 $targets=@();foreach($path in $Publication.Files.Keys){if($path-cnotmatch'^v2/(force-policy[.]txt|force-manifest[.]txt|full-policy-manifest[.]txt|full-policy-[0-9]{3}[.]txt|meta/[a-f0-9]{16}/(meta-quic[.]txt|manifest[.]json|manifest[.]seal[.]json))$'){throw 'CPV2_OUTPUT_SCOPE'};$target=[IO.Path]::GetFullPath((Join-Path $root $path));$check=$target;while($check.Length-gt$root.Length){if((Test-Path -LiteralPath $check)-and((Get-Item -LiteralPath $check).Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'CPV2_REPARSE_POINT'};$check=Split-Path -Parent $check};$targets+=@([pscustomobject]@{Path=$path;Target=$target})}
 foreach($target in $targets){[void][IO.Directory]::CreateDirectory((Split-Path -Parent $target.Target));$tmp=$target.Target+'.'+[guid]::NewGuid().ToString('N')+'.tmp';try{[IO.File]::WriteAllText($tmp,[string]$Publication.Files[$target.Path],(New-Object Text.UTF8Encoding($false)));Move-Item -LiteralPath $tmp -Destination $target.Target -Force}finally{if(Test-Path -LiteralPath $tmp){Remove-Item -LiteralPath $tmp -Force}}}
 foreach($p in $v1.Keys){if(-not[IO.File]::Exists($p)-or(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash-cne$v1[$p]){throw 'CPV2_V1_ROOT_CHANGED'}}
 [pscustomobject]@{Status='V2_DATA_ONLY_WRITTEN_LOCALLY';Path=(Join-Path $root 'v2');Files=$targets.Count;V1FilesVerified=$v1.Count;V1Changed=$false;Published=$false;CanApply=$false}
}
Export-ModuleMember -Function @('New-CloudPolicyV2Publication','Test-CloudPolicyV2Publication','Write-CloudPolicyV2Publication')
