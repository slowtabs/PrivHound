param(
    [ValidateSet('All','Bof','Harness')]
    [string]$Target = 'All'
    ,
    [ValidateSet('x64','x86')]
    [string]$Arch = 'x64'
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Build = Join-Path $PSScriptRoot 'build'
$Include = Join-Path $PSScriptRoot 'include'
$Src = Join-Path $PSScriptRoot 'src'
$Tests = Join-Path $PSScriptRoot 'tests'

New-Item -ItemType Directory -Path $Build -Force | Out-Null
$gcc = (Get-Command gcc -ErrorAction Stop).Source
$machine = (& $gcc -dumpmachine 2>$null | Select-Object -First 1).Trim()
if ($Arch -eq 'x64' -and $machine -notmatch 'x86_64|amd64') {
    throw "An x64 compiler is required for the default BOF build. Found '$machine'. Install an x64 MinGW/MSVC toolchain or run with -Arch x86 for local harness experiments."
}

$common = @('-Wall','-Wextra','-O2','-fno-stack-protector','-fno-asynchronous-unwind-tables','-mno-stack-arg-probe',"-I$Include",'-DWIN32_LEAN_AND_MEAN')
$sources = @(
    (Join-Path $Src 'ph_graph.c'),
    (Join-Path $Src 'ph_checks.c')
)

if ($Target -in @('All','Bof')) {
    $objects = @()
    foreach ($source in $sources + (Join-Path $Src 'entry.c')) {
        $object = Join-Path $Build (([IO.Path]::GetFileNameWithoutExtension($source)) + '.bof.o')
        & $gcc @common '-DBOF' '-ffreestanding' '-fno-builtin' '-c' $source '-o' $object
        if ($LASTEXITCODE -ne 0) { throw "BOF compilation failed: $source" }
        $objects += $object
    }
    $artifact = Join-Path $Build ("privhound.$Arch.bof.o")
    $ld = (Get-Command ld -ErrorAction Stop).Source
    & $ld '-r' '-o' $artifact @objects
    if ($LASTEXITCODE -ne 0) { throw 'BOF relocatable link failed' }
    Write-Host "Built $artifact" -ForegroundColor Green
}

if ($Target -in @('All','Harness')) {
    $harness = Join-Path $Build 'privhound_harness.exe'
    & $gcc @common '-DPH_HARNESS' $sources (Join-Path $Tests 'harness.c') '-ladvapi32' '-lntdll' '-o' $harness
    if ($LASTEXITCODE -ne 0) { throw 'Harness compilation failed' }
    Write-Host "Built $harness" -ForegroundColor Green
}

