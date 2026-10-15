[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ReferencePath,
    [Parameter(Mandatory)] [string]$CandidatePath,
    [string[]]$NodeKinds = @('PHUser','PHPrivTarget','PHEndpoint','PHTokenPrivilege','PHService'),
    [string[]]$EdgeKinds = @('PHHosts','PHHasSessionOn','PHHasPrivilege','PHCanEscalateTo','PHRunsAs','PHCanModifyService','PHCanWriteBinary')
)

$ErrorActionPreference = 'Stop'
$reference = Get-Content -LiteralPath $ReferencePath -Raw | ConvertFrom-Json
$candidate = Get-Content -LiteralPath $CandidatePath -Raw | ConvertFrom-Json

function Get-SelectedNodes($graph) {
    @($graph.graph.nodes | Where-Object {
        $kinds = @($_.kinds)
        @($kinds | Where-Object { $_ -in $NodeKinds }).Count -gt 0
    })
}

function Get-SelectedEdges($graph) {
    @($graph.graph.edges | Where-Object { $_.kind -in $EdgeKinds })
}

$referenceNodes = @{}
$candidateNodes = @{}
foreach ($node in (Get-SelectedNodes $reference)) { $referenceNodes[[string]$node.id] = $node }
foreach ($node in (Get-SelectedNodes $candidate)) { $candidateNodes[[string]$node.id] = $node }

$missingNodes = @($referenceNodes.Keys | Where-Object { -not $candidateNodes.ContainsKey($_) })
$extraNodes = @($candidateNodes.Keys | Where-Object { -not $referenceNodes.ContainsKey($_) })

function Edge-Key($edge) { "$($edge.start.value)|$($edge.end.value)|$($edge.kind)" }
$referenceEdges = @{}
$candidateEdges = @{}
foreach ($edge in (Get-SelectedEdges $reference)) { $referenceEdges[(Edge-Key $edge)] = $edge }
foreach ($edge in (Get-SelectedEdges $candidate)) { $candidateEdges[(Edge-Key $edge)] = $edge }

$missingEdges = @($referenceEdges.Keys | Where-Object { -not $candidateEdges.ContainsKey($_) })
$extraEdges = @($candidateEdges.Keys | Where-Object { -not $referenceEdges.ContainsKey($_) })

Write-Host "Reference selected nodes: $($referenceNodes.Count) | Candidate: $($candidateNodes.Count)"
Write-Host "Reference selected edges: $($referenceEdges.Count) | Candidate: $($candidateEdges.Count)"

if ($missingNodes.Count -gt 0) {
    Write-Warning "Missing nodes:"; $missingNodes | ForEach-Object { Write-Host "  $_" }
}
if ($extraNodes.Count -gt 0) {
    Write-Warning "Extra nodes:"; $extraNodes | ForEach-Object { Write-Host "  $_" }
}
if ($missingEdges.Count -gt 0) {
    Write-Warning "Missing edges:"; $missingEdges | ForEach-Object { Write-Host "  $_" }
}
if ($extraEdges.Count -gt 0) {
    Write-Warning "Extra edges:"; $extraEdges | ForEach-Object { Write-Host "  $_" }
}

if ($missingNodes.Count -or $missingEdges.Count) {
    exit 1
}

Write-Host 'Selected graph contract matches.' -ForegroundColor Green

