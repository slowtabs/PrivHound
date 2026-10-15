[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$GraphPath
)

$ErrorActionPreference = 'Stop'
$graph = Get-Content -LiteralPath $GraphPath -Raw | ConvertFrom-Json
$nodes = @($graph.graph.nodes)
$edges = @($graph.graph.edges)

if (-not ($nodes | Where-Object { $_.kinds -contains 'PHUser' })) { throw 'Iteration 1 lab graph has no PHUser node.' }
if (-not ($nodes | Where-Object { $_.kinds -contains 'PHEndpoint' })) { throw 'Iteration 1 lab graph has no PHEndpoint node.' }
if (-not ($nodes | Where-Object { $_.kinds -contains 'PHPrivTarget' })) { throw 'Iteration 1 lab graph has no PHPrivTarget node.' }

$serviceNodes = @($nodes | Where-Object { $_.kinds -contains 'PHService' })
$expected = @($serviceNodes | Where-Object { $_.properties.service_name -in @('PHLabVulnSvc','PHLabUserSvc','PHLabRegSvc','PHLabProgSvc') })
if ($expected.Count -eq 0) {
    throw 'No expected vulnerable PrivHound lab service was found. Run as the non-elevated lab user, not an elevated Administrator token.'
}

$serviceIds = @($expected | ForEach-Object { $_.id })
$weakEdges = @($edges | Where-Object {
    $_.kind -in @('PHCanModifyService','PHCanWriteBinary') -and $_.start.value -and $_.end.value -in $serviceIds
})
if ($weakEdges.Count -eq 0) { throw 'Expected vulnerable lab services were found, but no weak-service edge was emitted.' }

"Iteration 1 lab assertions passed: services=$($expected.Count) weak_edges=$($weakEdges.Count)"

