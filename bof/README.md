# PrivHound BOF — Iteration 1

This directory contains the first native vertical slice of PrivHound:

- host and current-user graph nodes;
- dangerous token-privilege collection;
- Windows service enumeration;
- service configuration and service-binary candidates;
- a standalone Windows harness;
- a Cobalt Strike BOF entry point named `go`.

The collector is read-only. It does not exploit findings, change services, validate credentials, or create persistence.

## Build

From the repository root, on a Windows machine with MinGW or a compatible GCC:

```powershell
.\bof\build.ps1                 # x64 BOF (requires an x64 compiler)
.\bof\build.ps1 -Arch x86       # compiler experiment; not a supported BOF artifact
```

Alternatively, from an x64 Native Tools Command Prompt for Visual Studio (recommended for the x64 iteration artifact):

```bat
bof\build-msvc.bat
```

Outputs:

```text
bof\build\privhound.x64.bof.o
bof\build\privhound_harness.exe
```

The `.o` file is the BOF artifact. The harness is for local testing without Cobalt Strike.

The relocatable link intentionally uses the toolchain linker directly so C runtime startup code is not added to the BOF. Inspect a built artifact with:

```powershell
.\tests\Inspect-PrivHoundBof.ps1 -BofPath .\bof\build\privhound.x64.bof.o -Architecture x64
```

## Run the harness

```powershell
.\bof\build\privhound_harness.exe -o C:\PrivHoundTest\bof.ndjson
```

The output is newline-delimited JSON records. It is intentionally an intermediate format so the BOF does not need to allocate one large BloodHound document inside Beacon.

## BOF integration

Build the artifact at `bof\build\privhound.x64.bof.o`, load `scripts\privhound.cna` in an authorized Cobalt Strike lab, and run the registered `privhound` command from a Beacon console.

Iteration 1 supports x64 Beacon sessions. The Aggressor wrapper refuses x86 sessions. Test in a disposable VM because a BOF executes inside Beacon and a native crash can affect that session.

