# Iteration 2 testing

Run the lab only in a disposable Windows VM. Take a clean snapshot before running the lab setup script. Do not run the vulnerable lab on a production or daily-use machine.

## Toolchain check

The recommended build uses Visual Studio C++ Build Tools. From an **x64 Native Tools Command Prompt for Visual Studio**:

```bat
bof\build-msvc.bat
```

That command builds and inspects the x64 BOF and also creates the standalone x64 harness used below.

An x64 MinGW-w64 toolchain is also supported. Its machine name must contain `x86_64` or `amd64`:

```powershell
gcc -dumpmachine
.\bof\build.ps1
.\tests\Inspect-PrivHoundBof.ps1 -BofPath .\bof\build\privhound.x64.bof.o -Architecture x64
```

If the compiler reports `mingw32`, use it only for compiler/harness experiments. Its x86 object is not an Iteration 2 release artifact:

```powershell
.\bof\build.ps1 -Arch x86
```

## Reference collection

From an elevated PowerShell window in the VM:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\lab\Setup-VulnLab.ps1
```

Confirm the prompt with `YES`, then use the test account printed by the setup script. Run the reference collector from a non-elevated test-user PowerShell:

```powershell
New-Item -ItemType Directory -Path C:\PrivHoundTest -Force | Out-Null
.\PrivHound.ps1 `
    -NoCredTest `
    -OutputPath C:\PrivHoundTest\powershell.json `
    -FindingsPath C:\PrivHoundTest\powershell_findings.json
```

## Harness collection

After building with one of the supported x64 toolchains above, run the same slice without Cobalt Strike:

```powershell
.\bof\build\privhound_harness.exe `
    -o C:\PrivHoundTest\bof.ndjson
.\scripts\Convert-PrivHoundNdjson.ps1 `
    -InputPath C:\PrivHoundTest\bof.ndjson `
    -OutputPath C:\PrivHoundTest\bof.json `
    -FindingsPath C:\PrivHoundTest\bof_findings.json
.\tests\Validate-PrivHoundOutput.ps1 `
    -NdjsonPath C:\PrivHoundTest\bof.ndjson `
    -OpenGraphPath C:\PrivHoundTest\bof.json
```

Compare the supported graph contract:

```powershell
.\tests\compare\Compare-PrivHoundGraphs.ps1 `
    -ReferencePath C:\PrivHoundTest\powershell.json `
    -CandidatePath C:\PrivHoundTest\bof.json
.\tests\Assert-Iteration2Lab.ps1 `
    -GraphPath C:\PrivHoundTest\bof.json
```

Iteration 2 acceptance expects `PHLabUnquotedSvc`, `C:\PrivHoundLab\FakePath`, both AlwaysInstallElevated policy values, and the no-prompt UAC policy created by the lab setup. Run the harness or BOF as the non-elevated `PHLabUser`; an elevated token intentionally suppresses writable-ACL escalation candidates.

## Cobalt Strike acceptance test

Only in an authorized Cobalt Strike lab:

1. Build `bof\build\privhound.x64.bof.o` (Iteration 2 requires an x64 Beacon).
2. Load `scripts\privhound.cna`.
3. Run `privhound` from a Beacon console with a matching built artifact.
4. Confirm the callback saves an `.ndjson` file.
5. Convert that file with `Convert-PrivHoundNdjson.ps1`.
6. Validate and compare the resulting graph.

The BOF does enumeration only. Do not test by exploiting the findings during this iteration.

## Cleanup

From an elevated PowerShell window:

```powershell
.\lab\Teardown-VulnLab.ps1
```

If teardown reports incomplete cleanup, revert the VM snapshot.

