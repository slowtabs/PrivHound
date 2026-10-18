[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$GraphPath
)

$ErrorActionPreference = 'Stop'
$graph = Get-Content -LiteralPath $GraphPath -Raw | ConvertFrom-Json
$nodes = @($graph.graph.nodes)
$edges = @($graph.graph.edges)

& (Join-Path $PSScriptRoot 'Assert-Iteration1Lab.ps1') -GraphPath $GraphPath

$unquoted = $nodes | Where-Object {
    $_.kinds -contains 'PHUnquotedPath' -and $_.properties.service_name -eq 'PHLabUnquotedSvc'
} | Select-Object -First 1
if (-not $unquoted) { throw 'Iteration 2 graph has no PHLabUnquotedSvc PHUnquotedPath node.' }
if (-not ($edges | Where-Object { $_.kind -eq 'PHCanHijackPath' -and $_.end.value -eq $unquoted.id })) {
    throw 'PHLabUnquotedSvc has no PHCanHijackPath edge.'
}

$writablePath = $nodes | Where-Object {
    $_.kinds -contains 'PHWritablePath' -and $_.properties.directory -ieq 'C:\PrivHoundLab\FakePath'
} | Select-Object -First 1
if (-not $writablePath) { throw 'Iteration 2 graph has no writable C:\PrivHoundLab\FakePath node.' }
if ($writablePath.properties.scope -ne 'machine') { throw 'The lab PATH node was not classified as machine scope.' }

$aie = $nodes | Where-Object { $_.kinds -contains 'PHRegistryMisconfig' } | Select-Object -First 1
if (-not $aie) { throw 'Iteration 2 graph has no AlwaysInstallElevated PHRegistryMisconfig node.' }
if (-not ($edges | Where-Object { $_.kind -eq 'PHCanExploit' -and $_.end.value -eq $aie.id })) {
    throw 'AlwaysInstallElevated has no PHCanExploit edge.'
}

$uac = $nodes | Where-Object { $_.kinds -contains 'PHUACBypass' } | Select-Object -First 1
if (-not $uac) { throw 'Iteration 2 graph has no PHUACBypass node.' }
if (-not ($edges | Where-Object { $_.kind -eq 'PHCanBypassUAC' -and $_.end.value -eq $uac.id })) {
    throw 'The UAC policy node has no PHCanBypassUAC edge.'
}

"Iteration 2 lab assertions passed: unquoted=1 writable_path=1 aie=1 uac=1"
