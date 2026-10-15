[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$InputPath,
    [Parameter(Mandatory)]
    [string]$OutputPath,
    [string]$FindingsPath
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $InputPath)) { throw "Input file not found: $InputPath" }

$nodes = [ordered]@{}
$edges = [ordered]@{}
$findings = [System.Collections.Generic.List[object]]::new()
$errors = [System.Collections.Generic.List[object]]::new()

foreach ($line in [IO.File]::ReadLines((Resolve-Path -LiteralPath $InputPath))) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    $record = $line | ConvertFrom-Json
    switch ($record.type) {
        'node' {
            if (-not $nodes.Contains($record.id)) {
                $nodes[$record.id] = [ordered]@{
                    id = [string]$record.id
                    kinds = @($record.kinds)
                    properties = $record.properties
                }
            }
        }
        'edge' {
            $key = "$($record.start)|$($record.end)|$($record.kind)"
            if (-not $edges.Contains($key)) {
                $edges[$key] = [ordered]@{
                    start = [ordered]@{ match_by = 'id'; value = [string]$record.start }
                    end = [ordered]@{ match_by = 'id'; value = [string]$record.end }
                    kind = [string]$record.kind
                    properties = $record.properties
                }
            }
        }
        'finding' { [void]$findings.Add($record) }
        'error' { [void]$errors.Add($record) }
    }
}

$payload = [ordered]@{
    metadata = [ordered]@{ source_kind = '' }
    graph = [ordered]@{
        nodes = @($nodes.Values)
        edges = @($edges.Values)
    }
}

$json = $payload | ConvertTo-Json -Depth 20
$resolvedOutput = if ([IO.Path]::IsPathRooted($OutputPath)) { [IO.Path]::GetFullPath($OutputPath) } else { [IO.Path]::GetFullPath((Join-Path (Get-Location) $OutputPath)) }
[IO.File]::WriteAllText($resolvedOutput, $json, [Text.UTF8Encoding]::new($false))

if ($FindingsPath) {
    $report = [ordered]@{
        hostname = ($nodes.Values | Where-Object { $_.kinds -contains 'PHEndpoint' } | Select-Object -First 1).properties.hostname
        generated_at = (Get-Date -Format o)
        findings = @($findings)
        errors = @($errors)
    }
    $resolvedFindings = if ([IO.Path]::IsPathRooted($FindingsPath)) { [IO.Path]::GetFullPath($FindingsPath) } else { [IO.Path]::GetFullPath((Join-Path (Get-Location) $FindingsPath)) }
    [IO.File]::WriteAllText($resolvedFindings, ($report | ConvertTo-Json -Depth 20), [Text.UTF8Encoding]::new($false))
}

Write-Host "OpenGraph JSON: $resolvedOutput" -ForegroundColor Green
Write-Host "Nodes: $($nodes.Count) | Edges: $($edges.Count) | Findings: $($findings.Count) | Errors: $($errors.Count)" -ForegroundColor Cyan
if ($errors.Count -gt 0) { Write-Warning "One or more BOF checks reported errors; inspect the findings report." }

