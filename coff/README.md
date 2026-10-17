# PrivHound COFF-loader test bundle

This directory contains the x64 PrivHound BOF and a locally built copy of
[Ap3x/COFF-Loader](https://github.com/Ap3x/COFF-Loader).

- Upstream commit: `6925595fd9ecd53023610cfe57170b22f00ddd6c`
- Build: Visual Studio 2022, CMake `Release`, x64, static MSVC runtime (`/MT`)
- `COFFLoader.exe` SHA-256: `9DCFBA8CEA5124F6F63F2CFA36F2DDE295A8215CE72F09AB8D2578CF46CC5A21`

Run from a normal, non-administrator PowerShell session in the disposable
Windows test VM:

```powershell
cd C:\PrivHound\coff
.\COFFLoader.exe go .\privhound.x64.bof.o
```

PrivHound's Iteration 1 BOF takes no arguments. The loader and BOF are x64.
The loader is statically linked and depends only on standard Windows system
DLLs, so a separate Visual C++ Redistributable installation is not required.
It also includes the two compatibility fixes recorded in
`Ap3x-COFF-Loader-PrivHound.patch`: support for COFF files with more than 255
sections and correct entry-point lookup for MSVC COMDAT sections.
Keep execution confined to an authorized, disposable lab VM.
