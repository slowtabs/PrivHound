#include "ph_checks.h"

#include <aclapi.h>
#include <winsvc.h>

#ifdef BOF
/* Current Windows SDK sddl.h declarations omit DECLSPEC_IMPORT. */
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ConvertSidToStringSidA(PSID Sid, LPSTR *StringSid);
#else
#include <sddl.h>
#endif

DECLSPEC_IMPORT LONG WINAPI RtlGetVersion(OSVERSIONINFOW *VersionInformation);

static int ph_len(const char *s) {
    int n = 0;
    if (!s) return 0;
    while (s[n]) n++;
    return n;
}

static void ph_copy_local(char *dst, int cap, const char *src) {
    int i = 0;
    if (!dst || cap <= 0) return;
    if (!src) src = "";
    while (i + 1 < cap && src[i]) { dst[i] = src[i]; i++; }
    dst[i] = 0;
}

static void ph_append_local(char *dst, int cap, const char *src) {
    int at = ph_len(dst);
    if (at < cap) ph_copy_local(dst + at, cap - at, src);
}

static void ph_uint_text(unsigned long value, char *out, int cap) {
    char digits[32];
    int n = 0;
    if (!out || cap <= 0) return;
    if (value == 0) { out[0] = '0'; out[1] = 0; return; }
    while (value && n < (int)sizeof(digits)) { digits[n++] = (char)('0' + (value % 10)); value /= 10; }
    int at = 0;
    while (n > 0 && at + 1 < cap) out[at++] = digits[--n];
    out[at] = 0;
}

static char ph_lower(char c) {
    return (c >= 'A' && c <= 'Z') ? (char)(c + ('a' - 'A')) : c;
}

static BOOL ph_equal_ci(const char *a, const char *b) {
    int i = 0;
    if (!a || !b) return a == b;
    while (a[i] && b[i]) {
        if (ph_lower(a[i]) != ph_lower(b[i])) return FALSE;
        i++;
    }
    return a[i] == 0 && b[i] == 0;
}

static void ph_emit_empty_edge(PH_GRAPH *g, const char *start, const char *end, const char *kind) {
    ph_emit_edge(g, start, end, kind, "{}");
}

static BOOL ph_get_process_token(HANDLE *token) {
    if (!token) return FALSE;
    *token = NULL;
    return OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, token);
}

static BOOL ph_access_check(PSECURITY_DESCRIPTOR sd, DWORD desired, GENERIC_MAPPING mapping) {
    HANDLE token = NULL, impersonation = NULL;
    PRIVILEGE_SET privileges;
    DWORD privilege_length = sizeof(privileges);
    DWORD granted = 0;
    BOOL access = FALSE;
    BOOL result;
    if (!sd || !ph_get_process_token(&token)) return FALSE;
    result = DuplicateToken(token, SecurityImpersonation, &impersonation);
    if (result) {
        result = AccessCheck(sd, impersonation, desired, &mapping, &privileges, &privilege_length, &granted, &access);
        if (!result) access = FALSE;
    }
    if (impersonation) CloseHandle(impersonation);
    if (token) CloseHandle(token);
    return access;
}

static BOOL ph_service_can_change(HANDLE service) {
    DWORD needed = 0;
    PSECURITY_DESCRIPTOR sd;
    GENERIC_MAPPING mapping;
    BOOL result;
    if (!service) return FALSE;
    QueryServiceObjectSecurity(service, DACL_SECURITY_INFORMATION, NULL, 0, &needed);
    if (!needed) return FALSE;
    sd = (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
    if (!sd) return FALSE;
    result = QueryServiceObjectSecurity(service, DACL_SECURITY_INFORMATION, sd, needed, &needed);
    mapping.GenericRead = STANDARD_RIGHTS_READ | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS | SERVICE_INTERROGATE | SERVICE_USER_DEFINED_CONTROL;
    mapping.GenericWrite = STANDARD_RIGHTS_WRITE | SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_STOP | SERVICE_PAUSE_CONTINUE | SERVICE_USER_DEFINED_CONTROL;
    mapping.GenericExecute = STANDARD_RIGHTS_EXECUTE | SERVICE_START | SERVICE_STOP | SERVICE_PAUSE_CONTINUE | SERVICE_INTERROGATE | SERVICE_USER_DEFINED_CONTROL;
    mapping.GenericAll = SERVICE_ALL_ACCESS;
    result = result && ph_access_check(sd, SERVICE_CHANGE_CONFIG, mapping);
    HeapFree(GetProcessHeap(), 0, sd);
    return result;
}

static BOOL ph_file_is_writable(const char *path) {
    PSECURITY_DESCRIPTOR sd = NULL;
    GENERIC_MAPPING mapping;
    DWORD error;
    BOOL result;
    if (!path || !path[0]) return FALSE;
    error = GetNamedSecurityInfoA((LPSTR)path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &sd);
    if (error != ERROR_SUCCESS || !sd) return FALSE;
    mapping.GenericRead = FILE_GENERIC_READ;
    mapping.GenericWrite = FILE_GENERIC_WRITE;
    mapping.GenericExecute = FILE_GENERIC_EXECUTE;
    mapping.GenericAll = FILE_ALL_ACCESS;
    result = ph_access_check(sd, FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER, mapping);
    LocalFree(sd);
    return result;
}

static void ph_binary_path(const char *service_path, char *out, int capacity) {
    int i = 0;
    int end = 0;
    if (!out || capacity <= 0) return;
    out[0] = 0;
    if (!service_path) return;
    while (service_path[i] == ' ' || service_path[i] == '\t') i++;
    if (service_path[i] == '"') {
        i++;
        while (service_path[i] && service_path[i] != '"' && end + 1 < capacity) out[end++] = service_path[i++];
    } else {
        while (service_path[i] && end + 1 < capacity) {
            if ((service_path[i] == '.' && (service_path[i+1] == 'e' || service_path[i+1] == 'E') &&
                 (service_path[i+2] == 'x' || service_path[i+2] == 'X') &&
                 (service_path[i+3] == 'e' || service_path[i+3] == 'E'))) {
                out[end++] = service_path[i++]; out[end++] = service_path[i++]; out[end++] = service_path[i++]; out[end++] = service_path[i++];
                break;
            }
            if (service_path[i] == ' ' || service_path[i] == '\t') break;
            out[end++] = service_path[i++];
        }
    }
    out[end] = 0;
}

static BOOL ph_is_system_account(const char *account) {
    return ph_equal_ci(account, "LocalSystem") || ph_equal_ci(account, "SYSTEM") ||
           ph_equal_ci(account, "NT AUTHORITY\\SYSTEM") || ph_equal_ci(account, "NT AUTHORITY/SYSTEM");
}

static BOOL ph_is_privileged_service_account(const char *account) {
    return ph_is_system_account(account) || ph_equal_ci(account, "LocalService") ||
           ph_equal_ci(account, "NT AUTHORITY\\LOCAL SERVICE") || ph_equal_ci(account, "NetworkService") ||
           ph_equal_ci(account, "NT AUTHORITY\\NETWORK SERVICE");
}

static const char *ph_service_state(DWORD state) {
    switch (state) {
    case SERVICE_RUNNING: return "Running";
    case SERVICE_STOPPED: return "Stopped";
    case SERVICE_START_PENDING: return "StartPending";
    case SERVICE_STOP_PENDING: return "StopPending";
    case SERVICE_PAUSED: return "Paused";
    default: return "Unknown";
    }
}

static const char *ph_start_mode(DWORD start_type) {
    switch (start_type) {
    case SERVICE_AUTO_START: return "Auto";
    case SERVICE_BOOT_START: return "Boot";
    case SERVICE_SYSTEM_START: return "System";
    case SERVICE_DEMAND_START: return "Manual";
    case SERVICE_DISABLED: return "Disabled";
    default: return "Unknown";
    }
}

static void ph_emit_core_node(PH_GRAPH *g, const char *id, const char *kind, const char *name,
                              const char *p1k, const char *p1v, const char *p2k, const char *p2v,
                              BOOL p3b, const char *p3k) {
    char props[4096];
    PH_JSON p;
    ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p);
    ph_json_add_string(&p, "name", name);
    if (p1k) ph_json_add_string(&p, p1k, p1v);
    if (p2k) ph_json_add_string(&p, p2k, p2v);
    if (p3k) ph_json_add_bool(&p, p3k, p3b);
    ph_json_add_string(&p, "hostname", g->hostname);
    ph_json_end_object(&p);
    ph_emit_node(g, id, kind, props);
}

void ph_collect_core(PH_GRAPH *g) {
    HANDLE token = NULL;
    char account[256];
    char domain[256];
    DWORD account_size = sizeof(account);
    DWORD domain_size = sizeof(domain);
    SID_NAME_USE sid_type;
    char os_version[64];
    char os_major[16], os_minor[16], os_build[16];
    OSVERSIONINFOW os;
    char props[4096];
    PH_JSON p;
    if (!g) return;

    ph_zero(account, sizeof(account));
    ph_zero(domain, sizeof(domain));
    ph_zero(os_version, sizeof(os_version));
    ph_zero(&os, sizeof(os));

    DWORD host_size = sizeof(g->hostname);
    if (!GetComputerNameA(g->hostname, &host_size)) ph_copy_local(g->hostname, sizeof(g->hostname), "UNKNOWN");
    DWORD user_size = sizeof(g->username);
    if (!GetUserNameA(g->username, &user_size)) ph_copy_local(g->username, sizeof(g->username), "UNKNOWN");

    if (ph_get_process_token(&token)) {
        TOKEN_USER *tu = NULL;
        DWORD needed = 0;
        GetTokenInformation(token, TokenUser, NULL, 0, &needed);
        if (needed) tu = (TOKEN_USER *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
        if (tu && GetTokenInformation(token, TokenUser, tu, needed, &needed)) {
            LPSTR sid_text = NULL;
            if (ConvertSidToStringSidA(tu->User.Sid, &sid_text)) {
                ph_copy_local(g->sid, sizeof(g->sid), sid_text);
                LocalFree((HLOCAL)sid_text);
            }
            LookupAccountSidA(NULL, tu->User.Sid, account, &account_size, domain, &domain_size, &sid_type);
            if (domain[0]) ph_copy_local(g->domain, sizeof(g->domain), domain);
            if (account[0]) ph_copy_local(g->username, sizeof(g->username), account);
        }
        if (tu) HeapFree(GetProcessHeap(), 0, tu);

        struct { DWORD TokenIsElevated; } elevation;
        DWORD elevation_size = sizeof(elevation);
        /* TokenElevation is information class 20; older MinGW headers omit its declaration. */
        if (GetTokenInformation(token, (TOKEN_INFORMATION_CLASS)20, &elevation, sizeof(elevation), &elevation_size)) {
            g->is_admin = elevation.TokenIsElevated ? TRUE : FALSE;
        }
        CloseHandle(token);
    }

    if (g->domain[0]) {
        ph_copy_local(g->identity, sizeof(g->identity), g->domain);
        int at = ph_len(g->identity);
        if (at + 1 < (int)sizeof(g->identity)) g->identity[at++] = '\\';
        ph_copy_local(g->identity + at, sizeof(g->identity) - at, g->username);
    } else {
        ph_copy_local(g->identity, sizeof(g->identity), g->username);
    }

    ph_id(g, "user", g->identity, g->current_user_id);
    ph_id(g, "target", "SYSTEM", g->system_id);
    ph_id(g, "target", "LocalAdmin", g->admin_id);
    ph_id(g, "computer", g->hostname, g->computer_id);

    os.dwOSVersionInfoSize = sizeof(os);
    if (RtlGetVersion(&os) >= 0) {
        ph_uint_text(os.dwMajorVersion, os_major, sizeof(os_major));
        ph_uint_text(os.dwMinorVersion, os_minor, sizeof(os_minor));
        ph_uint_text(os.dwBuildNumber, os_build, sizeof(os_build));
        ph_copy_local(os_version, sizeof(os_version), os_major);
        ph_append_local(os_version, sizeof(os_version), ".");
        ph_append_local(os_version, sizeof(os_version), os_minor);
        ph_append_local(os_version, sizeof(os_version), ".");
        ph_append_local(os_version, sizeof(os_version), os_build);
    } else ph_copy_local(os_version, sizeof(os_version), "Unknown");

    ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p);
    ph_json_add_string(&p, "name", g->identity); ph_json_add_string(&p, "username", g->username);
    ph_json_add_string(&p, "domain", g->domain); ph_json_add_string(&p, "sid", g->sid);
    ph_json_add_string(&p, "hostname", g->hostname); ph_json_add_bool(&p, "is_admin", g->is_admin); ph_json_end_object(&p);
    ph_emit_node(g, g->current_user_id, "[\"PHUser\"]", props);

    ph_emit_core_node(g, g->system_id, "[\"PHPrivTarget\"]", "NT AUTHORITY\\SYSTEM", "account", "NT AUTHORITY\\SYSTEM", NULL, NULL, FALSE, NULL);
    ph_emit_core_node(g, g->admin_id, "[\"PHPrivTarget\"]", "LOCAL ADMINISTRATOR", "account", "BUILTIN\\Administrators", NULL, NULL, FALSE, NULL);

    ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p);
    ph_json_add_string(&p, "name", g->hostname); ph_json_add_string(&p, "hostname", g->hostname);
    ph_json_add_string(&p, "os", "Windows"); ph_json_add_string(&p, "os_version", os_version);
#if defined(_WIN64)
    ph_json_add_string(&p, "arch", "AMD64");
#else
    ph_json_add_string(&p, "arch", "x86");
#endif
    ph_json_end_object(&p); ph_emit_node(g, g->computer_id, "[\"PHEndpoint\"]", props);

    ph_emit_empty_edge(g, g->computer_id, g->system_id, "PHHosts");
    ph_emit_empty_edge(g, g->computer_id, g->admin_id, "PHHosts");
    ph_emit_empty_edge(g, g->current_user_id, g->computer_id, "PHHasSessionOn");
}

static BOOL ph_is_dangerous(const char *name) {
    static const char *names[] = {
        "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege", "SeBackupPrivilege", "SeRestorePrivilege",
        "SeDebugPrivilege", "SeTakeOwnershipPrivilege", "SeLoadDriverPrivilege", "SeCreateTokenPrivilege",
        "SeTcbPrivilege", "SeManageVolumePrivilege"
    };
    for (int i=0; i<(int)(sizeof(names)/sizeof(names[0])); i++) if (ph_equal_ci(name, names[i])) return TRUE;
    return FALSE;
}

static const char *ph_priv_technique(const char *name) {
    if (ph_equal_ci(name, "SeImpersonatePrivilege") || ph_equal_ci(name, "SeAssignPrimaryTokenPrivilege")) return "Token impersonation via named pipe or COM";
    if (ph_equal_ci(name, "SeBackupPrivilege")) return "Read protected registry hives";
    if (ph_equal_ci(name, "SeRestorePrivilege")) return "Write protected files";
    if (ph_equal_ci(name, "SeDebugPrivilege")) return "Process injection into a privileged process";
    if (ph_equal_ci(name, "SeTakeOwnershipPrivilege")) return "Take ownership of protected objects";
    if (ph_equal_ci(name, "SeLoadDriverPrivilege")) return "Load a vulnerable kernel driver";
    if (ph_equal_ci(name, "SeCreateTokenPrivilege")) return "Create arbitrary tokens";
    if (ph_equal_ci(name, "SeTcbPrivilege")) return "Act as part of the operating system";
    if (ph_equal_ci(name, "SeManageVolumePrivilege")) return "Write protected files through volume management";
    return "Privilege abuse requires verification";
}

void ph_collect_token_privileges(PH_GRAPH *g) {
    HANDLE token = NULL;
    TOKEN_PRIVILEGES *privileges = NULL;
    DWORD needed = 0;
    if (!g) return;
    /* Match the PowerShell collector: privilege-escalation checks require a non-elevated context. */
    if (g->is_admin) return;
    if (!ph_get_process_token(&token)) { ph_emit_error(g, "TokenPrivileges", "OpenProcessToken failed"); return; }
    GetTokenInformation(token, TokenPrivileges, NULL, 0, &needed);
    if (!needed) { CloseHandle(token); ph_emit_error(g, "TokenPrivileges", "Token privilege query returned no data"); return; }
    privileges = (TOKEN_PRIVILEGES *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
    if (!privileges || !GetTokenInformation(token, TokenPrivileges, privileges, needed, &needed)) {
        if (privileges) HeapFree(GetProcessHeap(), 0, privileges);
        CloseHandle(token); ph_emit_error(g, "TokenPrivileges", "GetTokenInformation failed"); return;
    }
    for (DWORD i=0; i<privileges->PrivilegeCount; i++) {
        char name[128]; DWORD name_size = sizeof(name); LUID luid = privileges->Privileges[i].Luid;
        if (!LookupPrivilegeNameA(NULL, &luid, name, &name_size) || !ph_is_dangerous(name)) continue;
        char nid[33]; ph_id(g, "priv", name, nid);
        char props[2048]; PH_JSON p; ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p);
        ph_json_add_string(&p, "name", name); ph_json_add_string(&p, "privilege", name);
        ph_json_add_bool(&p, "enabled", (privileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) != 0);
        ph_json_add_string(&p, "hostname", g->hostname); ph_json_end_object(&p);
        ph_emit_node(g, nid, "[\"PHTokenPrivilege\"]", props);
        ph_emit_edge(g, g->current_user_id, nid, "PHHasPrivilege", "{\"mitre\":\"T1134.001\"}");
        char edge_props[2048]; PH_JSON ep; ph_json_init(&ep, edge_props, sizeof(edge_props)); ph_json_start_object(&ep);
        ph_json_add_string(&ep, "technique", ph_priv_technique(name)); ph_json_add_string(&ep, "mitre", "T1134.001"); ph_json_end_object(&ep);
        ph_emit_edge(g, nid, g->system_id, "PHCanEscalateTo", edge_props);
        ph_emit_finding(g, "Priv", (privileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) ? "HIGH" : "MEDIUM", name, ph_priv_technique(name));
    }
    HeapFree(GetProcessHeap(), 0, privileges);
    CloseHandle(token);
}

void ph_collect_services(PH_GRAPH *g) {
    SC_HANDLE scm = NULL;
    DWORD needed = 0, returned = 0, resume = 0;
    ENUM_SERVICE_STATUS_PROCESSA *services = NULL;
    if (!g) return;
    /* Match the PowerShell collector: service escalation checks require a non-elevated context. */
    if (g->is_admin) return;
    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) { ph_emit_error(g, "Services", "OpenSCManager failed"); return; }
    EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &needed, &returned, &resume, NULL);
    if (!needed) { CloseServiceHandle(scm); ph_emit_error(g, "Services", "Service enumeration returned no data"); return; }
    services = (ENUM_SERVICE_STATUS_PROCESSA *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
    if (!services) { CloseServiceHandle(scm); ph_emit_error(g, "Services", "Service enumeration allocation failed"); return; }
    if (!EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, (LPBYTE)services, needed, &needed, &returned, &resume, NULL)) {
        HeapFree(GetProcessHeap(), 0, services); CloseServiceHandle(scm); ph_emit_error(g, "Services", "EnumServicesStatusEx failed"); return;
    }
    for (DWORD i=0; i<returned; i++) {
        ENUM_SERVICE_STATUS_PROCESSA *entry = &services[i];
        SC_HANDLE service = OpenServiceA(scm, entry->lpServiceName, SERVICE_QUERY_CONFIG | READ_CONTROL);
        if (!service) continue;
        DWORD config_size = 0; QueryServiceConfigA(service, NULL, 0, &config_size);
        if (!config_size) { CloseServiceHandle(service); continue; }
        QUERY_SERVICE_CONFIGA *config = (QUERY_SERVICE_CONFIGA *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, config_size);
        if (!config || !QueryServiceConfigA(service, config, config_size, &config_size)) {
            if (config) HeapFree(GetProcessHeap(), 0, config);
            CloseServiceHandle(service);
            continue;
        }
        char binary[1024]; ph_binary_path(config->lpBinaryPathName, binary, sizeof(binary));
        BOOL can_modify = ph_service_can_change(service);
        BOOL bin_writable = ph_file_is_writable(binary);
        if (can_modify || bin_writable) {
            char nid[33]; ph_id(g, "service", entry->lpServiceName, nid);
            char props[4096]; PH_JSON p; ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p);
            char display[512]; ph_copy_local(display, sizeof(display), entry->lpDisplayName ? entry->lpDisplayName : entry->lpServiceName);
            char name[768]; ph_copy_local(name, sizeof(name), "SVC:"); ph_append_local(name, sizeof(name), entry->lpServiceName); ph_append_local(name, sizeof(name), "@"); ph_append_local(name, sizeof(name), g->hostname);
            ph_json_add_string(&p, "name", name); ph_json_add_string(&p, "service_name", entry->lpServiceName);
            ph_json_add_string(&p, "display_name", display); ph_json_add_string(&p, "start_name", config->lpServiceStartName);
            ph_json_add_string(&p, "binary_path", config->lpBinaryPathName); ph_json_add_string(&p, "start_mode", ph_start_mode(config->dwStartType));
            ph_json_add_string(&p, "state", ph_service_state(entry->ServiceStatusProcess.dwCurrentState));
            ph_json_add_string(&p, "hostname", g->hostname); ph_json_add_bool(&p, "can_modify", can_modify); ph_json_add_bool(&p, "bin_writable", bin_writable); ph_json_end_object(&p);
            ph_emit_node(g, nid, "[\"PHService\"]", props);
            if (ph_is_privileged_service_account(config->lpServiceStartName)) {
                char ep[2048]; PH_JSON e; ph_json_init(&e, ep, sizeof(ep)); ph_json_start_object(&e);
                ph_json_add_string(&e, "run_account", config->lpServiceStartName); ph_json_end_object(&e);
                ph_emit_edge(g, nid, g->system_id, "PHRunsAs", ep);
            }
            if (can_modify) {
                ph_emit_edge(g, g->current_user_id, nid, "PHCanModifyService", "{\"technique\":\"ChangeServiceConfig API\",\"mitre\":\"T1574.011\"}");
                char finding[2048]; ph_copy_local(finding, sizeof(finding), "Modifiable service '"); ph_append_local(finding, sizeof(finding), entry->lpServiceName); ph_append_local(finding, sizeof(finding), "' runs as "); ph_append_local(finding, sizeof(finding), config->lpServiceStartName);
                ph_emit_finding(g, "SvcPerms", "HIGH", finding, "Verify the service configuration in the lab before making changes");
            }
            if (bin_writable) {
                ph_emit_edge(g, g->current_user_id, nid, "PHCanWriteBinary", "{\"technique\":\"Replace service binary\",\"mitre\":\"T1574.010\"}");
                char finding[2048]; ph_copy_local(finding, sizeof(finding), "Writable service binary for '"); ph_append_local(finding, sizeof(finding), entry->lpServiceName); ph_append_local(finding, sizeof(finding), "': "); ph_append_local(finding, sizeof(finding), binary);
                ph_emit_finding(g, "SvcBin", "HIGH", finding, "Verify file permissions in the lab before making changes");
            }
        }
        HeapFree(GetProcessHeap(), 0, config);
        CloseServiceHandle(service);
    }
    HeapFree(GetProcessHeap(), 0, services);
    CloseServiceHandle(scm);
}

void ph_collect(PH_GRAPH *graph) {
    if (!graph) return;
    ph_collect_core(graph);
    ph_collect_token_privileges(graph);
    ph_collect_services(graph);
}

