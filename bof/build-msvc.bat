@echo off
setlocal

rem Run this from an x64 Native Tools Command Prompt for Visual Studio.
where cl.exe >nul 2>nul
if errorlevel 1 (
    echo ERROR: cl.exe was not found. Open an x64 Native Tools Command Prompt first.
    exit /b 1
)

if not exist "%~dp0build" mkdir "%~dp0build"

cl.exe /nologo /c /TC /GS- /Gs9999999 /Zl /O1 /Oi- /W3 /wd4996 /DBOF /DWIN32_LEAN_AND_MEAN ^
  /I"%~dp0include" "%~dp0src\privhound_bof.c" ^
  /Fo"%~dp0build\privhound.x64.bof.o"
if errorlevel 1 exit /b 1

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\tests\Inspect-PrivHoundBof.ps1" ^
  -BofPath "%~dp0build\privhound.x64.bof.o" -Architecture x64
if errorlevel 1 exit /b 1

pushd "%~dp0build"
cl.exe /nologo /TC /O2 /W3 /wd4996 /DWIN32_LEAN_AND_MEAN /I"%~dp0include" ^
  "%~dp0src\ph_graph.c" "%~dp0src\ph_checks.c" "%~dp0tests\harness.c" ^
  /Fe"privhound_harness.exe" /link /INCREMENTAL:NO Advapi32.lib Ntdll.lib
if errorlevel 1 (
  popd
  exit /b 1
)
popd

echo Built %~dp0build\privhound.x64.bof.o
echo Built %~dp0build\privhound_harness.exe

