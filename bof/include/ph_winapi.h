#pragma once

/*
 * Beacon resolves external functions from symbols named MODULE$Function.
 * Define those names before the Windows SDK headers declare the functions so
 * both MinGW and MSVC emit BOF-compatible Dynamic Function Resolution imports.
 */
#ifdef BOF
#define CloseHandle                 KERNEL32$CloseHandle
#define GetComputerNameA            KERNEL32$GetComputerNameA
#define GetCurrentProcess           KERNEL32$GetCurrentProcess
#define GetProcessHeap              KERNEL32$GetProcessHeap
#define HeapAlloc                   KERNEL32$HeapAlloc
#define HeapFree                    KERNEL32$HeapFree
#define LocalFree                   KERNEL32$LocalFree

#define AccessCheck                 ADVAPI32$AccessCheck
#define CloseServiceHandle          ADVAPI32$CloseServiceHandle
#define ConvertSidToStringSidA      ADVAPI32$ConvertSidToStringSidA
#define DuplicateToken              ADVAPI32$DuplicateToken
#define EnumServicesStatusExA       ADVAPI32$EnumServicesStatusExA
#define GetNamedSecurityInfoA       ADVAPI32$GetNamedSecurityInfoA
#define GetTokenInformation         ADVAPI32$GetTokenInformation
#define GetUserNameA                ADVAPI32$GetUserNameA
#define LookupAccountSidA           ADVAPI32$LookupAccountSidA
#define LookupPrivilegeNameA        ADVAPI32$LookupPrivilegeNameA
#define OpenProcessToken            ADVAPI32$OpenProcessToken
#define OpenSCManagerA              ADVAPI32$OpenSCManagerA
#define OpenServiceA                ADVAPI32$OpenServiceA
#define QueryServiceConfigA         ADVAPI32$QueryServiceConfigA
#define QueryServiceObjectSecurity  ADVAPI32$QueryServiceObjectSecurity

#define RtlGetVersion               NTDLL$RtlGetVersion
#endif

#include <windows.h>
