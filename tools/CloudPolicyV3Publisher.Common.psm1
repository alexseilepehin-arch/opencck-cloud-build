Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'ExactIpv4Collapse.Common.psm1') -DisableNameChecking

$script:seedBuild = '20261106230947'
$script:seedV2ManifestHash = '5ed539107b64adcea8d131213c890ba16176dc3bc4e1cfb41492128af551a0f45c3f17a334f4ccd5758c18f92afe606f9fdd728cc678c2c95171514c0e2ea5a0'
$script:chunkRows = 2000
$script:maxRows = 250000
$script:ascii = [Text.Encoding]::ASCII

if (-not ('Cpv3Full.PolicyRows' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.RegularExpressions;

namespace Cpv3Full {
    public sealed class PolicyRows {
        private static readonly Regex Dotted = new Regex(
            @"\A(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})(/(0|[1-9]|[12][0-9]|3[0-2]))?\z",
            RegexOptions.CultureInvariant);
        private readonly List<Interval> coverage = new List<Interval>();
        private readonly struct Interval {
            public readonly ulong Start, End;
            public Interval(ulong start, ulong end) { Start = start; End = end; }
        }

        public string[] Rows { get; }

        public PolicyRows(string[] source) {
            var keys = new SortedSet<ulong>();
            foreach (string row in source) {
                Match match = Dotted.Match(row);
                if (!match.Success) throw new ArgumentException("CPV3_IPV4_OR_CIDR_REQUIRED");
                ulong address = 0;
                for (int i = 1; i <= 4; i++) {
                    byte octet;
                    if (!Byte.TryParse(match.Groups[i].Value, NumberStyles.None, CultureInfo.InvariantCulture, out octet))
                        throw new ArgumentException("CPV3_IPV4_OCTET");
                    address = (address << 8) | octet;
                }
                int prefix = match.Groups[6].Success ? Int32.Parse(match.Groups[6].Value, CultureInfo.InvariantCulture) : 32;
                ulong size = 1UL << (32 - prefix);
                ulong network = address & ~(size - 1);
                if (!keys.Add((network << 6) | (uint)prefix)) throw new ArgumentException("CPV3_DUPLICATE_NORMALIZED_ROW");
            }

            Rows = new string[keys.Count];
            int index = 0;
            foreach (ulong key in keys) {
                ulong address = key >> 6;
                int prefix = (int)(key & 63);
                Rows[index++] = String.Format(CultureInfo.InvariantCulture, "{0}.{1}.{2}.{3}/{4}",
                    (address >> 24) & 255, (address >> 16) & 255, (address >> 8) & 255, address & 255, prefix);
                ulong end = address + (1UL << (32 - prefix)) - 1;
                if (coverage.Count == 0 || coverage[coverage.Count - 1].End + 1 < address) {
                    coverage.Add(new Interval(address, end));
                } else if (coverage[coverage.Count - 1].End < end) {
                    coverage[coverage.Count - 1] = new Interval(coverage[coverage.Count - 1].Start, end);
                }
            }
        }

        public bool Covers(PolicyRows other) {
            int i = 0;
            foreach (Interval required in other.coverage) {
                while (i < coverage.Count && coverage[i].End < required.Start) i++;
                if (i == coverage.Count || coverage[i].Start > required.Start || coverage[i].End < required.End) return false;
            }
            return true;
        }

        public string[] RowsAbsentFrom(PolicyRows other) {
            var remaining = new HashSet<string>(other.Rows, StringComparer.Ordinal);
            var missing = new List<string>();
            foreach (string row in Rows) if (!remaining.Contains(row)) missing.Add(row);
            return missing.ToArray();
        }
    }
}
'@
}

function Get-Cpv3Hash([string]$Text) {
    [Convert]::ToHexString([Security.Cryptography.SHA512]::HashData($script:ascii.GetBytes($Text))).ToLowerInvariant()
}

function Assert-Cpv3NoReparse([string]$Path) {
    for ($part = [IO.Path]::GetFullPath($Path); $part; $part = [IO.Path]::GetDirectoryName($part)) {
        if ((Test-Path -LiteralPath $part) -and ((Get-Item -LiteralPath $part -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'CPV3_REPARSE_POINT'
        }
    }
}

function Read-Cpv3Text([string]$Path, [int]$MaxBytes = 59999) {
    Assert-Cpv3NoReparse $Path
    $entry = Get-Item -LiteralPath $Path
    if ($entry.PSIsContainer -or $entry.Length -lt 1 -or $entry.Length -gt $MaxBytes) { throw 'CPV3_FILE_SIZE' }
    $bytes = [IO.File]::ReadAllBytes($entry.FullName)
    if ($bytes.Length -ne $entry.Length) { throw 'CPV3_FILE_CHANGED' }
    $text = $script:ascii.GetString($bytes)
    if (-not [Linq.Enumerable]::SequenceEqual[byte]($bytes, $script:ascii.GetBytes($text)) -or $text -cmatch '[^\x20-\x7e\x0a]') {
        throw 'CPV3_FILE_ENCODING'
    }
    return $text
}

function ConvertTo-Cpv3Json($Value) {
    return (ConvertTo-Json -InputObject $Value -Depth 12 -Compress)
}

function Read-Cpv3Json([string]$Text) {
    $value = ConvertFrom-Json -InputObject $Text -AsHashtable -Depth 12
    if ($value -isnot [Collections.IDictionary]) { throw 'CPV3_JSON_OBJECT_REQUIRED' }
    return $value
}

function Assert-Cpv3Keys($Value, [string[]]$Keys) {
    if ($Value -isnot [Collections.IDictionary] -or $Value.Keys.Count -ne $Keys.Count) { throw 'CPV3_SCHEMA_KEYS' }
    foreach ($key in $Value.Keys) {
        if ($key -cnotin $Keys) { throw 'CPV3_SCHEMA_KEYS' }
    }
}

function Assert-Cpv3Integer($Value, [long]$Min, [long]$Max) {
    if (($Value -isnot [int] -and $Value -isnot [long]) -or $Value -lt $Min -or $Value -gt $Max) { throw 'CPV3_INTEGER_RANGE' }
}

function Assert-Cpv3Hash($Value) {
    if ($Value -isnot [string] -or $Value -cnotmatch '\A[a-f0-9]{128}\z') { throw 'CPV3_SHA512_SCHEMA' }
}

function Assert-Cpv3Build($Value) {
    if ($Value -isnot [string] -or $Value -cnotmatch '\A[1-9][0-9]{13}\z') { throw 'CPV3_BUILD_ID' }
}

function Get-Cpv3SnapshotPath($Identity) {
    Assert-Cpv3Build $Identity.buildId
    Assert-Cpv3Hash $Identity.rowsSha512
    return "snapshots/$($Identity.buildId)/$($Identity.rowsSha512)"
}

function Assert-Cpv3Identity($Identity) {
    Assert-Cpv3Keys $Identity @('buildId', 'createdEpoch', 'coverageSha512', 'rowsSha512', 'count', 'manifestSha512')
    Assert-Cpv3Build $Identity.buildId
    Assert-Cpv3Integer $Identity.createdEpoch 0 253402300799
    Assert-Cpv3Integer $Identity.count 1 $script:maxRows
    Assert-Cpv3Hash $Identity.coverageSha512
    Assert-Cpv3Hash $Identity.rowsSha512
    Assert-Cpv3Hash $Identity.manifestSha512
}

function New-Cpv3ChunkSet([string[]]$Rows, [string]$Stem, [string]$Path, $Files) {
    $descriptors = [Collections.Generic.List[object]]::new()
    for ($start = 0; $start -lt $Rows.Count; $start += $script:chunkRows) {
        $count = [Math]::Min($script:chunkRows, $Rows.Count - $start)
        $text = [string]::Join("`n", $Rows, $start, $count)
        if ($text.Length -ge 60000) { throw 'CPV3_CHUNK_TOO_LARGE' }
        $file = '{0}-{1:D3}.txt' -f $Stem, ($descriptors.Count + 1)
        $Files.Add("$Path/$file", $text)
        $descriptors.Add([ordered]@{ file = $file; bytes = $text.Length; count = $count; sha512 = (Get-Cpv3Hash $text) })
    }
    return ,$descriptors.ToArray()
}

function New-Cpv3Snapshot([string]$BuildId, [long]$Epoch, [string[]]$Rows) {
    Assert-Cpv3Build $BuildId
    Assert-Cpv3Integer $Epoch 0 253402300799
    Assert-Cpv3Integer $Rows.Count 1 $script:maxRows
    $normalized = [Cpv3Full.PolicyRows]::new($Rows)
    $proof = Test-ExactIpv4Coverage -Before $Rows -After $normalized.Rows
    $identity = [ordered]@{
        buildId = $BuildId; createdEpoch = $Epoch; coverageSha512 = $proof.IntervalSHA512
        rowsSha512 = (Get-Cpv3Hash ($normalized.Rows -join "`n")); count = $normalized.Rows.Count
    }
    $path = Get-Cpv3SnapshotPath $identity
    $files = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
    $manifest = [ordered]@{ schema = 3; kind = 'full-snapshot' }
    foreach ($key in $identity.Keys) { $manifest.Add($key, $identity[$key]) }
    $manifest.Add('chunks', (New-Cpv3ChunkSet $normalized.Rows 'full-policy' $path $files))
    $text = ConvertTo-Cpv3Json $manifest
    $files.Add("$path/manifest.json", $text)
    $identity.Add('manifestSha512', (Get-Cpv3Hash $text))
    return [pscustomobject]@{ Identity = $identity; Path = $path; Normalized = $normalized; Files = $files }
}

function Read-Cpv3V2Snapshot([string]$ManifestPath, [string]$Pin = '') {
    $text = Read-Cpv3Text $ManifestPath
    if ($Pin -and (Get-Cpv3Hash $text) -cne $Pin) { throw 'CPV3_V2_MANIFEST_PIN' }
    $fields = @{}
    foreach ($line in $text.TrimEnd("`n").Split("`n")) {
        if ($line -cnotmatch '\A([a-z0-9_]+)=([A-Za-z0-9.-]+)\z' -or $fields.ContainsKey($Matches[1])) { throw 'CPV3_V2_MANIFEST_SCHEMA' }
        $fields.Add($Matches[1], $Matches[2])
    }
    foreach ($key in 'version','kind','build_id','chunk_count','expected_count','created_epoch') {
        if (-not $fields.ContainsKey($key)) { throw 'CPV3_V2_MANIFEST_SCHEMA' }
    }
    if ($fields.version -cne '2' -or $fields.kind -cne 'full' -or $fields.chunk_count -cnotmatch '\A[1-9][0-9]{0,2}\z' -or
        $fields.expected_count -cnotmatch '\A[1-9][0-9]{0,5}\z' -or $fields.created_epoch -cnotmatch '\A[0-9]{1,12}\z') { throw 'CPV3_V2_MANIFEST_SCHEMA' }
    $chunkCount = [int]$fields.chunk_count
    $expected = [int]$fields.expected_count
    if ($chunkCount -gt 125 -or $expected -gt $script:maxRows -or $fields.Count -ne 6 + $chunkCount * 4) { throw 'CPV3_V2_MANIFEST_COUNTS' }
    $rows = [Collections.Generic.List[string]]::new($expected)
    $root = Split-Path -Parent ([IO.Path]::GetFullPath($ManifestPath))
    for ($i = 1; $i -le $chunkCount; $i++) {
        $suffix = '{0:D3}' -f $i
        $key = "chunk_${suffix}_"
        $file = "full-policy-$suffix.txt"
        if ($fields[($key + 'file')] -cne $file -or $fields[($key + 'size')] -cnotmatch '\A[1-9][0-9]{0,4}\z' -or
            $fields[($key + 'count')] -cnotmatch '\A[1-9][0-9]{0,3}\z') { throw 'CPV3_V2_CHUNK_DESCRIPTOR' }
        Assert-Cpv3Hash $fields[($key + 'sha512')]
        $chunk = Read-Cpv3Text (Join-Path $root $file)
        $lines = $chunk.Split("`n")
        if ($chunk.Length -ne [int]$fields[($key + 'size')] -or (Get-Cpv3Hash $chunk) -cne $fields[($key + 'sha512')] -or
            $lines.Count -ne [int]$fields[($key + 'count')] -or $lines.Count -gt $script:chunkRows) { throw 'CPV3_V2_CHUNK_INTEGRITY' }
        $rows.AddRange($lines)
    }
    if ($rows.Count -ne $expected) { throw 'CPV3_V2_ROW_COUNT' }
    return New-Cpv3Snapshot $fields.build_id ([long]$fields.created_epoch) $rows.ToArray()
}

function New-Cpv3BaseReference($Base, $Target, $Files) {
    $old = $Base.Identity
    $new = $Target.Identity
    $baseRef = [ordered]@{
        buildId = $old.buildId; coverageSha512 = $old.coverageSha512; rowsSha512 = $old.rowsSha512
        count = $old.count; snapshotManifestSha512 = $old.manifestSha512
    }
    $mode = 'AB'
    $deltaHash = ''
    if ($old.coverageSha512 -ceq $new.coverageSha512) {
        $mode = 'SAME'
    } elseif ($Target.Normalized.Covers($Base.Normalized)) {
        $add = $Target.Normalized.RowsAbsentFrom($Base.Normalized)
        $remove = $Base.Normalized.RowsAbsentFrom($Target.Normalized)
        if ($add.Count + $remove.Count -le 4096 -and $remove.Count -le 1024) {
            # The base rows absent from the target must be redundant in its coverage.
            [void](Test-ExactIpv4Coverage -Before $Target.Normalized.Rows -After ($Target.Normalized.Rows + $remove))
            $path = "$($Target.Path)/from/$($old.rowsSha512)"
            $targetRef = [ordered]@{
                buildId = $new.buildId; coverageSha512 = $new.coverageSha512; rowsSha512 = $new.rowsSha512
                count = $new.count; manifestSha512 = $new.manifestSha512
            }
            $manifest = [ordered]@{
                schema = 3; kind = 'full-delta'; base = ([ordered]@{} + $baseRef); target = $targetRef
                addCount = $add.Count; removeCount = $remove.Count
                add = (New-Cpv3ChunkSet $add 'add' $path $Files)
                remove = (New-Cpv3ChunkSet $remove 'remove' $path $Files)
            }
            $text = ConvertTo-Cpv3Json $manifest
            $Files.Add("$path/manifest.json", $text)
            $deltaHash = Get-Cpv3Hash $text
            $mode = 'DELTA'
        }
    }
    $baseRef.Add('mode', $mode)
    $baseRef.Add('manifestSha512', $deltaHash)
    return $baseRef
}

function New-Cpv3Publication($Target, [object[]]$Bases) {
    $files = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
    $references = [Collections.Generic.List[object]]::new()
    foreach ($base in $Bases) { $references.Add((New-Cpv3BaseReference $base $Target $files)) }
    $index = ConvertTo-Cpv3Json ([ordered]@{ schema = 3; kind = 'full-index'; target = $Target.Identity; bases = $references.ToArray() })
    $files.Add("$($Target.Path)/index.json", $index)
    return [pscustomobject]@{ Target = $Target; Index = $index; IndexSha512 = (Get-Cpv3Hash $index); Bases = $references.ToArray(); Files = $files }
}

function Read-Cpv3Snapshot([string]$Root, $Identity) {
    Assert-Cpv3Identity $Identity
    $path = Get-Cpv3SnapshotPath $Identity
    $text = Read-Cpv3Text (Join-Path $Root "$path/manifest.json")
    if ((Get-Cpv3Hash $text) -cne $Identity.manifestSha512) { throw 'CPV3_HISTORY_SNAPSHOT_PIN' }
    $manifest = Read-Cpv3Json $text
    Assert-Cpv3Keys $manifest @('schema','kind','buildId','createdEpoch','coverageSha512','rowsSha512','count','chunks')
    if ($manifest.schema -cne 3 -or $manifest.kind -cne 'full-snapshot' -or $manifest.chunks -isnot [array] -or
        $manifest.chunks.Count -ne [Math]::Ceiling($Identity.count / [double]$script:chunkRows)) { throw 'CPV3_HISTORY_SNAPSHOT_SCHEMA' }
    $rows = [Collections.Generic.List[string]]::new([int]$Identity.count)
    for ($i = 0; $i -lt $manifest.chunks.Count; $i++) {
        $descriptor = $manifest.chunks[$i]
        Assert-Cpv3Keys $descriptor @('file','bytes','count','sha512')
        Assert-Cpv3Hash $descriptor.sha512
        Assert-Cpv3Integer $descriptor.bytes 1 59999
        Assert-Cpv3Integer $descriptor.count 1 $script:chunkRows
        $file = 'full-policy-{0:D3}.txt' -f ($i + 1)
        if ($descriptor.file -cne $file) { throw 'CPV3_HISTORY_CHUNK_FILENAME' }
        $chunk = Read-Cpv3Text (Join-Path $Root "$path/$file")
        $lines = $chunk.Split("`n")
        if ($lines.Count -ne $descriptor.count -or $chunk.Length -ne $descriptor.bytes -or (Get-Cpv3Hash $chunk) -cne $descriptor.sha512) {
            throw 'CPV3_HISTORY_CHUNK_INTEGRITY'
        }
        $rows.AddRange($lines)
    }
    $snapshot = New-Cpv3Snapshot $Identity.buildId $Identity.createdEpoch $rows.ToArray()
    foreach ($key in $snapshot.Identity.Keys) {
        if ($snapshot.Identity[$key] -cne $Identity[$key]) { throw 'CPV3_HISTORY_IDENTITY_MISMATCH' }
    }
    return $snapshot
}

function Read-Cpv3History([string]$HistoryRoot) {
    $catalog = Read-Cpv3Json (Read-Cpv3Text (Join-Path $HistoryRoot 'catalog.json') 500000)
    Assert-Cpv3Keys $catalog @('schema','kind','keepSeed','snapshots','publications')
    if ($catalog.schema -cne 3 -or $catalog.kind -cne 'full-history' -or $catalog.keepSeed -isnot [bool] -or
        $catalog.snapshots -isnot [array] -or $catalog.publications -isnot [array] -or
        $catalog.publications.Count -lt 1 -or $catalog.publications.Count -gt 3) { throw 'CPV3_HISTORY_SCHEMA' }
    $root = Join-Path $HistoryRoot 'v3/full'
    $snapshots = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($identity in $catalog.snapshots) {
        $snapshot = Read-Cpv3Snapshot $root $identity
        $snapshots.Add($snapshot.Identity.buildId, $snapshot)
    }
    $publications = [Collections.Generic.List[object]]::new()
    foreach ($reference in $catalog.publications) {
        Assert-Cpv3Keys $reference @('buildId','indexSha512')
        Assert-Cpv3Build $reference.buildId
        Assert-Cpv3Hash $reference.indexSha512
        if (-not $snapshots.ContainsKey($reference.buildId)) { throw 'CPV3_HISTORY_TARGET_NOT_FOUND' }
        $target = $snapshots[$reference.buildId]
        if ($publications.Count -and [long]$target.Identity.buildId -ge [long]$publications[$publications.Count - 1].Target.Identity.buildId) {
            throw 'CPV3_HISTORY_PUBLICATION_ORDER'
        }
        $text = Read-Cpv3Text (Join-Path $root "$($target.Path)/index.json")
        if ((Get-Cpv3Hash $text) -cne $reference.indexSha512) { throw 'CPV3_HISTORY_INDEX_PIN' }
        $index = Read-Cpv3Json $text
        Assert-Cpv3Keys $index @('schema','kind','target','bases')
        Assert-Cpv3Identity $index.target
        if ($index.schema -cne 3 -or $index.kind -cne 'full-index' -or $index.bases -isnot [array]) { throw 'CPV3_HISTORY_INDEX_SCHEMA' }
        $bases = [Collections.Generic.List[object]]::new()
        $rowsSeen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($base in $index.bases) {
            Assert-Cpv3Keys $base @('buildId','coverageSha512','rowsSha512','count','snapshotManifestSha512','mode','manifestSha512')
            Assert-Cpv3Build $base.buildId
            Assert-Cpv3Hash $base.rowsSha512
            if ([long]$base.buildId -ge [long]$target.Identity.buildId -or -not $rowsSeen.Add($base.rowsSha512) -or -not $snapshots.ContainsKey($base.buildId)) {
                throw 'CPV3_HISTORY_BASE_REFERENCE'
            }
            $bases.Add($snapshots[$base.buildId])
        }
        $verified = New-Cpv3Publication $target $bases.ToArray()
        if ($verified.Index -cne $text) { throw 'CPV3_HISTORY_INDEX_CONTENT' }
        foreach ($file in $verified.Files.Keys) {
            if ($file.EndsWith('/index.json', [StringComparison]::Ordinal)) { continue }
            if ((Read-Cpv3Text (Join-Path $root $file)) -cne $verified.Files[$file]) { throw 'CPV3_HISTORY_DELTA_CONTENT' }
        }
        $publications.Add($verified)
    }
    if ((Read-Cpv3Text (Join-Path $root 'latest.json')) -cne $publications[0].Index) { throw 'CPV3_HISTORY_LATEST_CONTENT' }
    return [pscustomobject]@{ Snapshots = $snapshots; Publications = $publications.ToArray(); KeepSeed = $catalog.keepSeed }
}

function Write-Cpv3Text([string]$Path, [string]$Text, [int]$MaxBytes = 59999) {
    if ($Text.Length -lt 1 -or $Text.Length -gt $MaxBytes -or $Text -cmatch '[^\x20-\x7e\x0a]') { throw 'CPV3_OUTPUT_ENCODING_OR_SIZE' }
    Assert-Cpv3NoReparse $Path
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path))
    [IO.File]::WriteAllBytes($Path, $script:ascii.GetBytes($Text))
}

function Write-Cpv3Tree([string]$Root, [object[]]$Snapshots, [object[]]$Publications) {
    foreach ($snapshot in $Snapshots) {
        foreach ($file in $snapshot.Files.Keys) { Write-Cpv3Text (Join-Path $Root $file) $snapshot.Files[$file] }
    }
    foreach ($publication in $Publications) {
        foreach ($file in $publication.Files.Keys) { Write-Cpv3Text (Join-Path $Root $file) $publication.Files[$file] }
    }
    Write-Cpv3Text (Join-Path $Root 'latest.json') $Publications[0].Index
}

function Install-Cpv3ArtifactTree([string]$ArtifactRoot, [object[]]$Snapshots, [object[]]$Publications) {
    Assert-Cpv3NoReparse $ArtifactRoot
    if (-not [IO.Directory]::Exists($ArtifactRoot)) { throw 'CPV3_ARTIFACT_ROOT_REQUIRED' }
    $parent = Join-Path $ArtifactRoot 'v3'
    $destination = Join-Path $parent 'full'
    Assert-Cpv3NoReparse $destination
    if (Test-Path -LiteralPath $destination) { throw 'CPV3_ARTIFACT_DESTINATION_EXISTS' }
    $staging = Join-Path $parent ('full-' + [guid]::NewGuid().ToString('N') + '.tmp')
    try {
        Write-Cpv3Tree $staging $Snapshots $Publications
        [IO.Directory]::Move($staging, $destination)
    } finally {
        if ([IO.Directory]::Exists($staging)) {
            # The resolved child was chosen by this process and never comes from a manifest.
            $actual = (Get-Item -LiteralPath $staging -Force).FullName
            if ([IO.Path]::GetDirectoryName($actual) -ceq [IO.Path]::GetFullPath($parent) -and $actual -ceq [IO.Path]::GetFullPath($staging)) {
                Assert-Cpv3NoReparse $actual
                Remove-Item -LiteralPath $actual -Force -Recurse
            }
        }
    }
}

function Publish-CloudPolicyV3Full {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ArtifactRoot,
        [Parameter(Mandatory)][string]$HistoryOutputRoot,
        [string]$PriorHistoryRoot,
        [string]$SeedV2ManifestPath,
        [switch]$RetireSeed,
        [DateTimeOffset]$NowUtc = [DateTimeOffset]::UtcNow
    )
    $ArtifactRoot = [IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath($ArtifactRoot))
    $HistoryOutputRoot = [IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath($HistoryOutputRoot))
    $separator = [IO.Path]::DirectorySeparatorChar
    if (Test-Path -LiteralPath $HistoryOutputRoot) { throw 'CPV3_NEW_HISTORY_ROOT_REQUIRED' }
    if ($ArtifactRoot.StartsWith($HistoryOutputRoot + $separator, [StringComparison]::OrdinalIgnoreCase) -or
        $HistoryOutputRoot.StartsWith($ArtifactRoot + $separator, [StringComparison]::OrdinalIgnoreCase)) { throw 'CPV3_HISTORY_ARTIFACT_OVERLAP' }
    if ($SeedV2ManifestPath -and $RetireSeed) { throw 'CPV3_SEED_MODE_CONFLICT' }
    Assert-Cpv3NoReparse $HistoryOutputRoot
    $target = Read-Cpv3V2Snapshot (Join-Path $ArtifactRoot 'v2/full-policy-manifest.txt')
    $prior = if ($PriorHistoryRoot) { Read-Cpv3History $PriorHistoryRoot }
    $all = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $keepSeed = -not $RetireSeed -and ($null -eq $prior -or $prior.KeepSeed -or $SeedV2ManifestPath)
    if ($null -ne $prior) {
        foreach ($snapshot in $prior.Snapshots.Values) { $all.Add($snapshot.Identity.buildId, $snapshot) }
        if ([long]$target.Identity.buildId -lt [long]$prior.Publications[0].Target.Identity.buildId) { throw 'CPV3_TARGET_REGRESSION' }
    }
    if ($SeedV2ManifestPath) {
        $seed = Read-Cpv3V2Snapshot $SeedV2ManifestPath $script:seedV2ManifestHash
        if ($seed.Identity.buildId -cne $script:seedBuild) { throw 'CPV3_SEED_BUILD_ID' }
        if ($all.ContainsKey($script:seedBuild) -and $all[$script:seedBuild].Identity.manifestSha512 -cne $seed.Identity.manifestSha512) {
            throw 'CPV3_SEED_CONFLICT'
        }
        $all[$script:seedBuild] = $seed
    }
    if ($all.ContainsKey($target.Identity.buildId) -and $all[$target.Identity.buildId].Identity.manifestSha512 -cne $target.Identity.manifestSha512) {
        throw 'CPV3_BUILD_ID_COLLISION'
    }
    $all[$target.Identity.buildId] = $target

    $orderedSnapshots = @($all.Values | Sort-Object -Property { [long]$_.Identity.buildId } -Descending)
    $distinct = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $retained = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $cutoff = $NowUtc.AddDays(-30).ToUnixTimeSeconds()
    foreach ($snapshot in $orderedSnapshots) {
        $id = $snapshot.Identity
        $stateKey = $id.rowsSha512 + $id.coverageSha512
        $recentDistinct = $distinct.Add($stateKey) -and $distinct.Count -le 12
        if ($id.createdEpoch -ge $cutoff -or $recentDistinct -or ($keepSeed -and $id.buildId -ceq $script:seedBuild)) {
            $retained.Add($id.buildId, $snapshot)
        }
    }
    $retained[$target.Identity.buildId] = $target

    if ($null -ne $prior -and $prior.Publications[0].Target.Identity.buildId -ceq $target.Identity.buildId) {
        # A retry must keep the same bytes at every immutable URL.
        $publications = $prior.Publications
    } else {
        $bases = [Collections.Generic.List[object]]::new()
        $indexedRows = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        if ($keepSeed -and $retained.ContainsKey($script:seedBuild) -and [long]$script:seedBuild -lt [long]$target.Identity.buildId) {
            $pinned = $retained[$script:seedBuild]
            [void]$indexedRows.Add($pinned.Identity.rowsSha512)
            $bases.Add($pinned)
        }
        foreach ($snapshot in $orderedSnapshots) {
            $id = $snapshot.Identity
            if ([long]$id.buildId -lt [long]$target.Identity.buildId -and $retained.ContainsKey($id.buildId) -and $indexedRows.Add($id.rowsSha512)) {
                $bases.Add($snapshot)
            }
        }
        $current = New-Cpv3Publication $target $bases.ToArray()
        $publications = @($current)
        if ($null -ne $prior) { $publications += @($prior.Publications | Select-Object -First 2) }
    }
    foreach ($publication in $publications) {
        $retained[$publication.Target.Identity.buildId] = $publication.Target
        foreach ($base in $publication.Bases) { $retained[$base.buildId] = $all[$base.buildId] }
    }
    $snapshots = @($retained.Values | Sort-Object -Property { [long]$_.Identity.buildId } -Descending)
    $catalog = [ordered]@{
        schema = 3; kind = 'full-history'; keepSeed = $keepSeed
        snapshots = @($snapshots | ForEach-Object { $_.Identity })
        publications = @($publications | ForEach-Object { [ordered]@{ buildId = $_.Target.Identity.buildId; indexSha512 = $_.IndexSha512 } })
    }
    Write-Cpv3Tree (Join-Path $HistoryOutputRoot 'v3/full') $snapshots $publications
    Write-Cpv3Text (Join-Path $HistoryOutputRoot 'catalog.json') (ConvertTo-Cpv3Json $catalog) 500000
    Install-Cpv3ArtifactTree $ArtifactRoot $snapshots $publications
    return [pscustomobject]@{
        Status = 'V3_FULL_READY'; BuildId = $target.Identity.buildId; CoverageSha512 = $target.Identity.coverageSha512
        RowsSha512 = $target.Identity.rowsSha512; Rows = $target.Identity.count; SnapshotCount = $snapshots.Count
        PublicationCount = $publications.Count; IndexSha512 = $publications[0].IndexSha512; HistoryRoot = $HistoryOutputRoot
    }
}

function Copy-VerifiedCloudPolicyV3Channel {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$HistoryRoot, [Parameter(Mandatory)][string]$ArtifactRoot)
    $verified = Read-Cpv3History $HistoryRoot
    Install-Cpv3ArtifactTree ([IO.Path]::GetFullPath($ArtifactRoot)) @($verified.Snapshots.Values) $verified.Publications
    return [pscustomobject]@{
        Status = 'V3_FULL_VERIFIED_FALLBACK'; BuildId = $verified.Publications[0].Target.Identity.buildId
        IndexSha512 = $verified.Publications[0].IndexSha512
    }
}

Export-ModuleMember -Function @('Publish-CloudPolicyV3Full','Copy-VerifiedCloudPolicyV3Channel')
