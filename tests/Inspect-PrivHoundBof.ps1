[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$BofPath,
    [ValidateSet('x64','x86')]
    [string]$Architecture = 'x64'
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $BofPath)) { throw "BOF not found: $BofPath" }
$resolvedBof = (Resolve-Path -LiteralPath $BofPath).Path

$objdump = Get-Command objdump -ErrorAction SilentlyContinue
$nm = Get-Command nm -ErrorAction SilentlyContinue
$inspectionMode = $null
$headers = @()
$symbols = @()

if ($objdump -and $nm) {
    $savedErrorPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $headers = @(& $objdump.Source -f $resolvedBof 2>$null)
    $objdumpExitCode = $LASTEXITCODE
    $ErrorActionPreference = $savedErrorPreference
    if ($objdumpExitCode -eq 0 -and ($headers | Select-String 'file format')) {
        $symbols = @(& $nm.Source -g $resolvedBof 2>$null)
        if ($LASTEXITCODE -ne 0) { throw 'nm failed to inspect the BOF.' }
        $inspectionMode = 'gnu'
    }
}

if (-not $inspectionMode) {
    $dumpbin = Get-Command dumpbin.exe -ErrorAction SilentlyContinue
    if (-not $dumpbin) {
        $dumpbinPath = Get-ChildItem -Path "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\*\VC\Tools\MSVC\*\bin\Hostx64\x64\dumpbin.exe" -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending | Select-Object -First 1
        if ($dumpbinPath) { $dumpbin = Get-Command $dumpbinPath.FullName }
    }
    if (-not $dumpbin) { throw 'Could not inspect this COFF object: install GNU objdump/nm or Visual Studio dumpbin.' }
    $headers = @(& $dumpbin.Source /headers $resolvedBof 2>&1)
    if ($LASTEXITCODE -ne 0) { throw 'dumpbin failed to inspect the BOF headers.' }
    $symbols = @(& $dumpbin.Source /symbols $resolvedBof 2>&1)
    if ($LASTEXITCODE -ne 0) { throw 'dumpbin failed to inspect the BOF symbols.' }
    $inspectionMode = 'msvc'
}

if ($inspectionMode -eq 'gnu') {
    $format = [string](($headers | Select-String 'file format' | Select-Object -First 1).Line)
    $expectedFormat = if ($Architecture -eq 'x64') { 'pe-x86-64|pei-x86-64' } else { 'pe-i386|pei-i386' }
    if ($format -notmatch $expectedFormat) { throw "Expected $Architecture BOF, but objdump reported: $format" }
    $entry = $symbols | Where-Object { $_ -match '\b(_?go)$' -and $_ -match '\sT\s' }
    $undefined = @($symbols | Where-Object { $_ -match '\sU\s' })
} else {
    $machinePattern = if ($Architecture -eq 'x64') { '\b8664 machine \(x64\)' } else { '\b14C machine \(x86\)' }
    if (-not ($headers | Select-String -Pattern $machinePattern)) { throw "dumpbin did not identify the object as $Architecture." }
    $entry = $symbols | Where-Object { $_ -match 'SECT[0-9A-F]+.*External\s+\|\s+_?go\s*$' }
    $undefined = @($symbols | Where-Object { $_ -match '\bUNDEF\b.*\bExternal\b.*\|' })
}

if (-not $entry) { throw 'BOF entry point go was not found as a defined external symbol.' }

$forbidden = @('WinMain','mainCRTStartup','__main','chkstk','__ImageBase','memcpy','memset')
foreach ($name in $forbidden) {
    if ($undefined | Select-String -SimpleMatch $name) { throw "BOF contains an unexpected unresolved runtime/startup symbol: $name" }
}

$requiredImports = @(
    'KERNEL32$GetComputerNameA',
    'ADVAPI32$GetUserNameA',
    'ADVAPI32$GetTokenInformation',
    'ADVAPI32$OpenSCManagerA',
    'NTDLL$RtlGetVersion',
    'BeaconOutput'
)
foreach ($name in $requiredImports) {
    if (-not ($undefined | Select-String -SimpleMatch $name)) { throw "Expected BOF import is missing: $name" }
}

$unexpected = @($undefined | Where-Object {
    $_ -notmatch '(KERNEL32|ADVAPI32|NTDLL)\$[A-Za-z0-9_]+' -and $_ -notmatch 'BeaconOutput'
})
if ($unexpected.Count -gt 0) {
    throw "BOF contains unresolved imports that do not use Beacon DFR naming: $($unexpected -join '; ')"
}

$directDfr = @($undefined | Where-Object {
    $_ -match '(KERNEL32|ADVAPI32|NTDLL)\$[A-Za-z0-9_]+' -and $_ -notmatch '__imp_'
})
if ($directDfr.Count -gt 0) {
    throw "BOF contains direct DFR calls instead of import-pointer symbols: $($directDfr -join '; ')"
}

"BOF artifact inspection passed: $resolvedBof ($Architecture, $inspectionMode)"
