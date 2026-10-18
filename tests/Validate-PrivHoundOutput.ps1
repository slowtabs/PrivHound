[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$NdjsonPath,
    [string]$OpenGraphPath
)

$ErrorActionPreference = 'Stop'
$records = [System.Collections.Generic.List[object]]::new()
$nodes = @{}
$edges = @{}
$errors = [System.Collections.Generic.List[string]]::new()
$lineNumber = 0

function Get-PHExpectedId([string]$Hostname, [string]$Type, [string]$Name) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes("$Hostname|$Type|$Name")
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').Substring(0, 32).ToUpperInvariant()
    } finally {
        $sha.Dispose()
    }
}

foreach ($line in [IO.File]::ReadLines((Resolve-Path -LiteralPath $NdjsonPath))) {
    $lineNumber++
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    try { $record = $line | ConvertFrom-Json }
    catch { throw "Invalid JSON at line $lineNumber`: $($_.Exception.Message)" }
    [void]$records.Add($record)
    if ($record.type -eq 'node') {
        if (-not $record.id -or -not $record.kinds -or $null -eq $record.properties) { throw "Malformed node at line $lineNumber" }
        if ([string]$record.id -notmatch '^[0-9A-F]{32}$') { throw "Node ID must be 32 uppercase hexadecimal characters at line $lineNumber`: $($record.id)" }
        if ($nodes.ContainsKey([string]$record.id)) { throw "Duplicate node id at line $lineNumber`: $($record.id)" }
        $nodes[[string]$record.id] = $record
    } elseif ($record.type -eq 'edge') {
        if (-not $record.start -or -not $record.end -or -not $record.kind -or $null -eq $record.properties) { throw "Malformed edge at line $lineNumber" }
        $key = "$($record.start)|$($record.end)|$($record.kind)"
        if ($edges.ContainsKey($key)) { throw "Duplicate edge at line $lineNumber`: $key" }
        $edges[$key] = $record
    } elseif ($record.type -notin @('finding','error')) {
        throw "Unknown record type '$($record.type)' at line $lineNumber"
    }
}

foreach ($node in $nodes.Values) {
    $idType = $null
    $idName = $null
    if ($node.kinds -contains 'PHUser') { $idType = 'user'; $idName = [string]$node.properties.name }
    elseif ($node.kinds -contains 'PHEndpoint') { $idType = 'computer'; $idName = [string]$node.properties.hostname }
    elseif ($node.kinds -contains 'PHTokenPrivilege') { $idType = 'priv'; $idName = [string]$node.properties.privilege }
    elseif ($node.kinds -contains 'PHService') { $idType = 'service'; $idName = [string]$node.properties.service_name }
    elseif ($node.kinds -contains 'PHUnquotedPath') { $idType = 'unquoted'; $idName = [string]$node.properties.service_name }
    elseif ($node.kinds -contains 'PHWritablePath') { $idType = 'pathdir'; $idName = [string]$node.properties.directory }
    elseif ($node.kinds -contains 'PHRegistryMisconfig') { $idType = 'regkey'; $idName = 'AIE' }
    elseif ($node.kinds -contains 'PHUACBypass') {
        $idType = 'uac'
        $idName = if ([string]$node.properties.name -match '^UAC:DISABLED@') { 'LUA_disabled' } else { 'NoPrompt' }
    }
    if ($idType -and $node.properties.hostname -and $idName) {
        $expectedId = Get-PHExpectedId ([string]$node.properties.hostname) $idType $idName
        if ([string]$node.id -cne $expectedId) { throw "Node ID parity failure for $idType '$idName': expected $expectedId, got $($node.id)" }
    }
}

foreach ($edge in $edges.Values) {
    if (-not $nodes.ContainsKey([string]$edge.start)) { [void]$errors.Add("Edge start node missing: $($edge.start)") }
    if (-not $nodes.ContainsKey([string]$edge.end)) { [void]$errors.Add("Edge end node missing: $($edge.end)") }
}

if ($OpenGraphPath) {
    $graph = Get-Content -LiteralPath $OpenGraphPath -Raw | ConvertFrom-Json
    if ($null -eq $graph.metadata -or $null -eq $graph.graph) { throw 'OpenGraph payload is missing metadata or graph' }
    if (@($graph.graph.nodes).Count -ne $nodes.Count) { throw 'OpenGraph node count does not match NDJSON' }
    if (@($graph.graph.edges).Count -ne $edges.Count) { throw 'OpenGraph edge count does not match NDJSON' }
}

if ($errors.Count -gt 0) {
    $errors | ForEach-Object { Write-Error $_ }
    exit 1
}

"valid records=$($records.Count) nodes=$($nodes.Count) edges=$($edges.Count) findings=$(@($records | Where-Object type -eq 'finding').Count) errors=$(@($records | Where-Object type -eq 'error').Count)"

