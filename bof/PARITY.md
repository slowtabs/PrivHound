# BOF feature-parity roadmap

The PowerShell collector currently exposes 29 checks. BOF parity is being delivered in cohesive, testable iterations so shared native primitives are validated before more checks depend on them.

Legend: `done` is implemented and covered by local structural validation; `accepted` has also passed its positive VM fixture; `planned` is not implemented yet.

| PowerShell check | BOF status | Planned iteration |
|---|---:|---:|
| WeakServicePermissions | accepted | 1 |
| UnquotedServicePaths | accepted | 2 |
| DLLHijacking | accepted | 2 |
| AlwaysInstallElevated | accepted | 2 |
| TokenPrivileges | done | 1 |
| ScheduledTasks | planned | 3 |
| AutoRuns | planned | 3 |
| ServiceRegistryKeys | planned | 3 |
| StoredCredentials | planned | 4 |
| GPPPasswords | planned | 4 |
| UnattendFiles | planned | 4 |
| PSHistory | planned | 4 |
| SensitiveFiles | planned | 4 |
| UACBypass | accepted | 2 |
| WritableProgramDirs | planned | 3 |
| CrossUserProfiles | planned | 5 |
| CredentialLoginPaths | planned | 5 |
| CrossUserPrivileges | planned | 5 |
| JITAdminTools | planned | 5 |
| PrintSpooler | planned | 6 |
| WSUSConfig | planned | 6 |
| SCCMCredentials | planned | 4 |
| COMHijacking | planned | 6 |
| NamedPipePermissions | planned | 6 |
| CachedCredentials | planned | 5 |
| WMISubscriptions | planned | 6 |
| WebClientRelay | planned | 6 |
| ServiceRecoveryActions | planned | 3 |
| ShadowCopyFiles | planned | 6 |

## Iteration acceptance

Each iteration must pass:

1. x64 MSVC compilation and BOF import/entry-point inspection;
2. standalone harness execution without collector errors;
3. NDJSON-to-OpenGraph conversion and schema/ID validation;
4. positive assertions against `lab/Setup-VulnLab.ps1` from a non-elevated `PHLabUser` session;
5. PowerShell-versus-BOF graph comparison for the checks in that iteration;
6. direct execution with an authorized x64 BOF loader or Beacon in the disposable VM.

Credential discovery and validation will need explicit runtime controls before Iterations 4 and 5. The default BOF should not emit plaintext passwords, and active credential validation should remain opt-in because it creates authentication events and can trigger account lockout policy.
