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

static BOOL ph_get_process_token(HANDLE *token);

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

static BOOL ph_starts_ci(const char *value, const char *prefix) {
    int i = 0;
    if (!value || !prefix) return FALSE;
    while (prefix[i]) {
        if (!value[i] || ph_lower(value[i]) != ph_lower(prefix[i])) return FALSE;
        i++;
    }
    return TRUE;
}

static BOOL ph_ends_ci(const char *value, const char *suffix) {
    int value_length = ph_len(value), suffix_length = ph_len(suffix);
    if (suffix_length > value_length) return FALSE;
    return ph_equal_ci(value + value_length - suffix_length, suffix);
}

static BOOL ph_has_space(const char *value) {
    int i = 0;
    if (!value) return FALSE;
    while (value[i]) {
        if (value[i] == ' ' || value[i] == '\t') return TRUE;
        i++;
    }
    return FALSE;
}

static void ph_trim_path(char *value) {
    int start = 0, end, length;
    if (!value) return;
    length = ph_len(value);
    while (start < length && (value[start] == ' ' || value[start] == '\t' || value[start] == '"')) start++;
    end = length;
    while (end > start && (value[end-1] == ' ' || value[end-1] == '\t' || value[end-1] == '"')) end--;
    if (start > 0) {
        int i;
        for (i = start; i < end; i++) value[i-start] = value[i];
        end -= start;
    }
    while (end > 3 && (value[end-1] == '\\' || value[end-1] == '/')) end--;
    value[end] = 0;
}

static void ph_parent_path(const char *path, char *out, int capacity) {
    int length, slash = -1;
    if (!out || capacity <= 0) return;
    out[0] = 0;
    if (!path) return;
    length = ph_len(path);
    for (int i = 0; i < length; i++) if (path[i] == '\\' || path[i] == '/') slash = i;
    if (slash < 0) return;
    if (slash == 2 && path[1] == ':') slash++;
    for (int i = 0; i < slash && i + 1 < capacity; i++) out[i] = path[i];
    if (slash < capacity) out[slash] = 0;
    else out[capacity-1] = 0;
}

static BOOL ph_reg_dword(HKEY root, const char *subkey, const char *name, DWORD *value) {
    HKEY key = NULL;
    DWORD type = 0, size = sizeof(DWORD), data = 0;
    LONG result;
    if (!value) return FALSE;
    result = RegOpenKeyExA(root, subkey, 0, KEY_QUERY_VALUE, &key);
    if (result != ERROR_SUCCESS) return FALSE;
    result = RegQueryValueExA(key, name, NULL, &type, (LPBYTE)&data, &size);
    RegCloseKey(key);
    if (result != ERROR_SUCCESS || type != REG_DWORD || size != sizeof(DWORD)) return FALSE;
    *value = data;
    return TRUE;
}

static char *ph_environment_value(const char *name) {
    DWORD needed;
    char *value;
    needed = GetEnvironmentVariableA(name, NULL, 0);
    if (!needed) return NULL;
    value = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, needed + 1);
    if (!value) return NULL;
    if (!GetEnvironmentVariableA(name, value, needed)) {
        HeapFree(GetProcessHeap(), 0, value);
        return NULL;
    }
    return value;
}

static char *ph_reg_string(HKEY root, const char *subkey, const char *name) {
    HKEY key = NULL;
    DWORD type = 0, size = 0;
    char *value = NULL;
    if (RegOpenKeyExA(root, subkey, 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) return NULL;
    if (RegQueryValueExA(key, name, NULL, &type, NULL, &size) != ERROR_SUCCESS ||
        (type != REG_SZ && type != REG_EXPAND_SZ) || !size) {
        RegCloseKey(key);
        return NULL;
    }
    value = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size + 2);
    if (!value || RegQueryValueExA(key, name, NULL, &type, (LPBYTE)value, &size) != ERROR_SUCCESS) {
        if (value) HeapFree(GetProcessHeap(), 0, value);
        RegCloseKey(key);
        return NULL;
    }
    RegCloseKey(key);
    return value;
}

static BOOL ph_path_list_contains(const char *list, const char *candidate) {
    int at = 0;
    char segment[2048];
    if (!list || !candidate) return FALSE;
    while (list[at]) {
        int n = 0;
        while (list[at] && list[at] != ';') {
            if (n + 1 < (int)sizeof(segment)) segment[n++] = list[at];
            at++;
        }
        if (list[at] == ';') at++;
        segment[n] = 0;
        ph_trim_path(segment);
        if (ph_equal_ci(segment, candidate)) return TRUE;
    }
    return FALSE;
}

static BOOL ph_token_has_admin_group(void) {
    HANDLE token = NULL;
    TOKEN_GROUPS *groups = NULL;
    DWORD needed = 0;
    BOOL found = FALSE;
    if (!ph_get_process_token(&token)) return FALSE;
    GetTokenInformation(token, TokenGroups, NULL, 0, &needed);
    if (needed) groups = (TOKEN_GROUPS *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
    if (groups && GetTokenInformation(token, TokenGroups, groups, needed, &needed)) {
        for (DWORD i = 0; i < groups->GroupCount; i++) {
            LPSTR sid_text = NULL;
            if (ConvertSidToStringSidA(groups->Groups[i].Sid, &sid_text)) {
                if (ph_equal_ci(sid_text, "S-1-5-32-544")) found = TRUE;
                LocalFree((HLOCAL)sid_text);
            }
            if (found) break;
        }
    }
    if (groups) HeapFree(GetProcessHeap(), 0, groups);
    CloseHandle(token);
    return found;
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
    /* AccessCheck requires an impersonation token, so this handle also needs TOKEN_DUPLICATE. */
    if (!sd || !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &token)) return FALSE;
    result = DuplicateToken(token, SecurityImpersonation, &impersonation);
    if (result) {
        result = AccessCheck(sd, impersonation, desired, &mapping, &privileges, &privilege_length, &granted, &access);
        if (!result) access = FALSE;
    }
    if (impersonation) CloseHandle(impersonation);
    if (token) CloseHandle(token);
    return access;
}

static BOOL ph_can_open_service(SC_HANDLE scm, const char *name, DWORD desired) {
    SC_HANDLE service;
    if (!scm || !name || !name[0]) return FALSE;
    service = OpenServiceA(scm, name, desired);
    if (!service) return FALSE;
    CloseServiceHandle(service);
    return TRUE;
}

static BOOL ph_service_can_change(SC_HANDLE scm, const char *name) {
    /* Opening the service for a right asks the SCM to evaluate the caller's effective token. */
    return ph_can_open_service(scm, name, SERVICE_CHANGE_CONFIG) ||
           ph_can_open_service(scm, name, WRITE_DAC) ||
           ph_can_open_service(scm, name, WRITE_OWNER);
}

static BOOL ph_file_allows_open(const char *path, DWORD desired) {
    HANDLE file;
    if (!path || !path[0]) return FALSE;
    file = CreateFileA(path, desired, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    CloseHandle(file);
    return TRUE;
}

static BOOL ph_file_allows(const char *path, DWORD desired) {
    PSECURITY_DESCRIPTOR sd = NULL;
    GENERIC_MAPPING mapping;
    DWORD error;
    BOOL result;
    if (!path || !path[0]) return FALSE;
    error = GetNamedSecurityInfoA((LPSTR)path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &sd);
    if (error == ERROR_SUCCESS && sd) {
        mapping.GenericRead = FILE_GENERIC_READ;
        mapping.GenericWrite = FILE_GENERIC_WRITE;
        mapping.GenericExecute = FILE_GENERIC_EXECUTE;
        mapping.GenericAll = FILE_ALL_ACCESS;
        result = ph_access_check(sd, desired, mapping);
        LocalFree(sd);
        if (result) return TRUE;
    }
    /* Some third-party BOF loaders do not preserve token duplication semantics reliably. */
    return ph_file_allows_open(path, desired);
}

static BOOL ph_file_is_writable(const char *path) {
    DWORD attributes;
    char parent[4096];
    if (!path || !path[0]) return FALSE;
    attributes = GetFileAttributesA(path);
    if (attributes == INVALID_FILE_ATTRIBUTES) return FALSE;
    /* Match Test-WritableAcl: any one of content/create, WRITE_DAC, or WRITE_OWNER qualifies. */
    if (ph_file_allows(path, FILE_WRITE_DATA) || ph_file_allows(path, WRITE_DAC) || ph_file_allows(path, WRITE_OWNER)) return TRUE;
    if (attributes & FILE_ATTRIBUTE_DIRECTORY) return FALSE;
    ph_parent_path(path, parent, sizeof(parent));
    if (!parent[0] || !ph_file_allows(parent, FILE_ADD_FILE)) return FALSE;
    return ph_file_allows(path, DELETE) || ph_file_allows(parent, FILE_DELETE_CHILD);
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
    ph_json_add_string(&p, "collector", "PrivHound BOF"); ph_json_add_string(&p, "collector_version", "2.1");
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
    HKEY services_key = NULL;
    DWORD index = 0;
    if (!g) return;
    /* Match the PowerShell collector: service escalation checks require a non-elevated context. */
    if (g->is_admin) return;
    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) { ph_emit_error(g, "Services", "OpenSCManager failed"); return; }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services", 0,
                      KEY_ENUMERATE_SUB_KEYS, &services_key) != ERROR_SUCCESS) {
        CloseServiceHandle(scm); ph_emit_error(g, "Services", "Could not enumerate the Services registry key"); return;
    }
    for (;;) {
        char service_name[512];
        DWORD service_name_length = sizeof(service_name);
        LONG enum_result = RegEnumKeyExA(services_key, index++, service_name, &service_name_length,
                                         NULL, NULL, NULL, NULL);
        SC_HANDLE service;
        if (enum_result == ERROR_NO_MORE_ITEMS) break;
        if (enum_result != ERROR_SUCCESS) continue;
        service = OpenServiceA(scm, service_name, SERVICE_QUERY_CONFIG);
        if (!service) continue;
        DWORD config_size = 0; QueryServiceConfigA(service, NULL, 0, &config_size);
        if (!config_size) { CloseServiceHandle(service); continue; }
        QUERY_SERVICE_CONFIGA *config = (QUERY_SERVICE_CONFIGA *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, config_size);
        if (!config || !QueryServiceConfigA(service, config, config_size, &config_size)) {
            if (config) HeapFree(GetProcessHeap(), 0, config);
            CloseServiceHandle(service);
            continue;
        }
        if (!(config->dwServiceType & SERVICE_WIN32)) {
            HeapFree(GetProcessHeap(), 0, config); CloseServiceHandle(service); continue;
        }
        char binary[1024]; ph_binary_path(config->lpBinaryPathName, binary, sizeof(binary));
        BOOL can_modify = ph_service_can_change(scm, service_name);
        BOOL bin_writable = ph_file_is_writable(binary);
        if (can_modify || bin_writable) {
            SERVICE_STATUS_PROCESS status;
            DWORD status_size = 0;
            SC_HANDLE status_service;
            ph_zero(&status, sizeof(status));
            status_service = OpenServiceA(scm, service_name, SERVICE_QUERY_STATUS);
            if (status_service) {
                QueryServiceStatusEx(status_service, SC_STATUS_PROCESS_INFO, (LPBYTE)&status,
                                     sizeof(status), &status_size);
                CloseServiceHandle(status_service);
            }
            char nid[33]; ph_id(g, "service", service_name, nid);
            char props[4096]; PH_JSON p; ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p);
            char display[512]; ph_copy_local(display, sizeof(display), config->lpDisplayName ? config->lpDisplayName : service_name);
            char name[768]; ph_copy_local(name, sizeof(name), "SVC:"); ph_append_local(name, sizeof(name), service_name); ph_append_local(name, sizeof(name), "@"); ph_append_local(name, sizeof(name), g->hostname);
            ph_json_add_string(&p, "name", name); ph_json_add_string(&p, "service_name", service_name);
            ph_json_add_string(&p, "display_name", display); ph_json_add_string(&p, "start_name", config->lpServiceStartName);
            ph_json_add_string(&p, "binary_path", config->lpBinaryPathName); ph_json_add_string(&p, "start_mode", ph_start_mode(config->dwStartType));
            ph_json_add_string(&p, "state", status.dwCurrentState ? ph_service_state(status.dwCurrentState) : "Unknown");
            ph_json_add_string(&p, "hostname", g->hostname); ph_json_add_bool(&p, "can_modify", can_modify); ph_json_add_bool(&p, "bin_writable", bin_writable); ph_json_end_object(&p);
            ph_emit_node(g, nid, "[\"PHService\"]", props);
            if (ph_is_privileged_service_account(config->lpServiceStartName)) {
                char ep[2048]; PH_JSON e; ph_json_init(&e, ep, sizeof(ep)); ph_json_start_object(&e);
                ph_json_add_string(&e, "run_account", config->lpServiceStartName); ph_json_end_object(&e);
                ph_emit_edge(g, nid, g->system_id, "PHRunsAs", ep);
            }
            if (can_modify) {
                ph_emit_edge(g, g->current_user_id, nid, "PHCanModifyService", "{\"technique\":\"ChangeServiceConfig API\",\"mitre\":\"T1574.011\"}");
                char finding[2048]; ph_copy_local(finding, sizeof(finding), "Modifiable service '"); ph_append_local(finding, sizeof(finding), service_name); ph_append_local(finding, sizeof(finding), "' runs as "); ph_append_local(finding, sizeof(finding), config->lpServiceStartName);
                ph_emit_finding(g, "SvcPerms", "HIGH", finding, "Verify the service configuration in the lab before making changes");
            }
            if (bin_writable) {
                ph_emit_edge(g, g->current_user_id, nid, "PHCanWriteBinary", "{\"technique\":\"Replace service binary\",\"mitre\":\"T1574.010\"}");
                char finding[2048]; ph_copy_local(finding, sizeof(finding), "Writable service binary for '"); ph_append_local(finding, sizeof(finding), service_name); ph_append_local(finding, sizeof(finding), "': "); ph_append_local(finding, sizeof(finding), binary);
                ph_emit_finding(g, "SvcBin", "HIGH", finding, "Verify file permissions in the lab before making changes");
            }
        }
        HeapFree(GetProcessHeap(), 0, config);
        CloseServiceHandle(service);
    }
    RegCloseKey(services_key);
    CloseServiceHandle(scm);
}

static BOOL ph_unquoted_hijack_path(const char *service_path, char *hijack, int capacity) {
    char expanded[4096];
    char build[4096];
    char parent[4096];
    char windows[512];
    char system32[768];
    const char *path = service_path;
    int at = 0, build_length = 0;
    DWORD expanded_length;
    if (!hijack || capacity <= 0) return FALSE;
    hijack[0] = 0;
    if (!service_path) return FALSE;
    while (*path == ' ' || *path == '\t') path++;
    if (!*path || *path == '"' || !ph_has_space(path)) return FALSE;

    expanded_length = ExpandEnvironmentStringsA(path, expanded, sizeof(expanded));
    if (expanded_length && expanded_length <= sizeof(expanded)) path = expanded;

    windows[0] = 0;
    if (GetWindowsDirectoryA(windows, sizeof(windows))) {
        ph_copy_local(system32, sizeof(system32), windows);
        ph_append_local(system32, sizeof(system32), "\\System32\\");
        if (ph_starts_ci(path, system32)) return FALSE;
    }

    build[0] = 0;
    while (path[at]) {
        int token_start, token_end;
        while (path[at] == ' ' || path[at] == '\t') at++;
        if (!path[at]) break;
        token_start = at;
        while (path[at] && path[at] != ' ' && path[at] != '\t') at++;
        token_end = at;
        if (build_length && build_length + 1 < (int)sizeof(build)) build[build_length++] = ' ';
        for (int i = token_start; i < token_end && build_length + 1 < (int)sizeof(build); i++) build[build_length++] = path[i];
        build[build_length] = 0;
        if (ph_ends_ci(build, ".exe")) break;
        ph_parent_path(build, parent, sizeof(parent));
        if (parent[0] && ph_file_is_writable(parent)) {
            ph_copy_local(hijack, capacity, build);
            ph_append_local(hijack, capacity, ".exe");
            return TRUE;
        }
    }
    return FALSE;
}

void ph_collect_unquoted_service_paths(PH_GRAPH *g) {
    SC_HANDLE scm = NULL;
    HKEY services_key = NULL;
    DWORD index = 0;
    if (!g || g->is_admin) return;
    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) { ph_emit_error(g, "Unquoted", "OpenSCManager failed"); return; }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services", 0,
                      KEY_ENUMERATE_SUB_KEYS, &services_key) != ERROR_SUCCESS) {
        CloseServiceHandle(scm); ph_emit_error(g, "Unquoted", "Could not enumerate the Services registry key"); return;
    }
    for (;;) {
        char service_name[512];
        DWORD service_name_length = sizeof(service_name);
        LONG enum_result = RegEnumKeyExA(services_key, index++, service_name, &service_name_length,
                                         NULL, NULL, NULL, NULL);
        SC_HANDLE service;
        DWORD config_size = 0;
        QUERY_SERVICE_CONFIGA *config = NULL;
        char hijack[4096];
        if (enum_result == ERROR_NO_MORE_ITEMS) break;
        if (enum_result != ERROR_SUCCESS) continue;
        service = OpenServiceA(scm, service_name, SERVICE_QUERY_CONFIG);
        if (!service) continue;
        QueryServiceConfigA(service, NULL, 0, &config_size);
        if (config_size) config = (QUERY_SERVICE_CONFIGA *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, config_size);
        if (!config || !QueryServiceConfigA(service, config, config_size, &config_size)) {
            if (config) HeapFree(GetProcessHeap(), 0, config);
            CloseServiceHandle(service);
            continue;
        }
        if (!(config->dwServiceType & SERVICE_WIN32)) {
            HeapFree(GetProcessHeap(), 0, config); CloseServiceHandle(service); continue;
        }
        if (ph_unquoted_hijack_path(config->lpBinaryPathName, hijack, sizeof(hijack))) {
            char nid[33], props[8192], edge_props[4096], finding[4096], name[1024];
            PH_JSON p, ep;
            ph_id(g, "unquoted", service_name, nid);
            ph_copy_local(name, sizeof(name), "UNQUOTED:");
            ph_append_local(name, sizeof(name), service_name);
            ph_append_local(name, sizeof(name), "@");
            ph_append_local(name, sizeof(name), g->hostname);
            ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p);
            ph_json_add_string(&p, "name", name);
            ph_json_add_string(&p, "service_name", service_name);
            ph_json_add_string(&p, "original_path", config->lpBinaryPathName);
            ph_json_add_string(&p, "hijack_path", hijack);
            ph_json_add_string(&p, "start_name", config->lpServiceStartName);
            ph_json_add_string(&p, "hostname", g->hostname);
            ph_json_end_object(&p);
            ph_emit_node(g, nid, "[\"PHUnquotedPath\"]", props);
            ph_json_init(&ep, edge_props, sizeof(edge_props)); ph_json_start_object(&ep);
            ph_json_add_string(&ep, "hijack_path", hijack);
            ph_json_add_string(&ep, "mitre", "T1574.009");
            ph_json_end_object(&ep);
            ph_emit_edge(g, g->current_user_id, nid, "PHCanHijackPath", edge_props);
            if (ph_is_system_account(config->lpServiceStartName)) {
                ph_json_init(&ep, edge_props, sizeof(edge_props)); ph_json_start_object(&ep);
                ph_json_add_string(&ep, "run_account", config->lpServiceStartName);
                ph_json_end_object(&ep);
                ph_emit_edge(g, nid, g->system_id, "PHRunsAs", edge_props);
            }
            ph_copy_local(finding, sizeof(finding), "Unquoted '");
            ph_append_local(finding, sizeof(finding), service_name);
            ph_append_local(finding, sizeof(finding), "': ");
            ph_append_local(finding, sizeof(finding), config->lpBinaryPathName);
            ph_emit_finding(g, "Unquoted", "HIGH", finding, "Verify the writable intermediate path before placing a test file");
        }
        HeapFree(GetProcessHeap(), 0, config);
        CloseServiceHandle(service);
    }
    RegCloseKey(services_key);
    CloseServiceHandle(scm);
}

void ph_collect_writable_path(PH_GRAPH *g) {
    char *process_path = NULL, *machine_raw = NULL, *machine_path = NULL, *seen = NULL;
    char windows[512];
    int at = 0, seen_length = 0;
    if (!g || g->is_admin) return;
    process_path = ph_environment_value("PATH");
    if (!process_path) { ph_emit_error(g, "DLLHijack", "PATH is unavailable"); return; }
    machine_raw = ph_reg_string(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", "Path");
    if (machine_raw) {
        DWORD machine_needed = ExpandEnvironmentStringsA(machine_raw, NULL, 0);
        if (machine_needed) {
            machine_path = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, machine_needed + 1);
            if (machine_path && !ExpandEnvironmentStringsA(machine_raw, machine_path, machine_needed)) {
                HeapFree(GetProcessHeap(), 0, machine_path); machine_path = NULL;
            }
        }
    }
    seen = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ph_len(process_path) + 2);
    windows[0] = 0;
    GetWindowsDirectoryA(windows, sizeof(windows));
    ph_trim_path(windows);
    while (process_path[at]) {
        char raw[2048], expanded[4096], nid[33], props[8192], edge_props[1024], name[4608], finding[4608];
        PH_JSON p, ep;
        int n = 0;
        DWORD expanded_length;
        while (process_path[at] && process_path[at] != ';') {
            if (n + 1 < (int)sizeof(raw)) raw[n++] = process_path[at];
            at++;
        }
        if (process_path[at] == ';') at++;
        raw[n] = 0;
        ph_trim_path(raw);
        if (!raw[0]) continue;
        expanded_length = ExpandEnvironmentStringsA(raw, expanded, sizeof(expanded));
        if (!expanded_length || expanded_length > sizeof(expanded)) ph_copy_local(expanded, sizeof(expanded), raw);
        ph_trim_path(expanded);
        if (!expanded[0] || ph_equal_ci(expanded, windows) ||
            (ph_starts_ci(expanded, windows) && expanded[ph_len(windows)] == '\\')) continue;
        if (seen && ph_path_list_contains(seen, expanded)) continue;
        if (seen && seen_length + ph_len(expanded) + 2 < ph_len(process_path) + 2) {
            ph_copy_local(seen + seen_length, ph_len(process_path) + 2 - seen_length, expanded);
            seen_length += ph_len(expanded);
            seen[seen_length++] = ';'; seen[seen_length] = 0;
        }
        if (!ph_file_is_writable(expanded)) continue;
        const char *scope = (machine_path && ph_path_list_contains(machine_path, expanded)) ? "machine" : "user/process";
        ph_id(g, "pathdir", expanded, nid);
        ph_copy_local(name, sizeof(name), "PATH:"); ph_append_local(name, sizeof(name), expanded);
        ph_append_local(name, sizeof(name), "@"); ph_append_local(name, sizeof(name), g->hostname);
        ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p);
        ph_json_add_string(&p, "name", name); ph_json_add_string(&p, "directory", expanded);
        ph_json_add_string(&p, "scope", scope); ph_json_add_string(&p, "hostname", g->hostname);
        ph_json_end_object(&p);
        ph_emit_node(g, nid, "[\"PHWritablePath\"]", props);
        ph_json_init(&ep, edge_props, sizeof(edge_props)); ph_json_start_object(&ep);
        ph_json_add_string(&ep, "scope", scope); ph_json_end_object(&ep);
        ph_emit_edge(g, g->current_user_id, nid, "PHCanWriteTo", edge_props);
        ph_copy_local(finding, sizeof(finding), "Writable "); ph_append_local(finding, sizeof(finding), scope);
        ph_append_local(finding, sizeof(finding), " collector PATH: "); ph_append_local(finding, sizeof(finding), expanded);
        ph_append_local(finding, sizeof(finding), " (privileged DLL loading unverified)");
        ph_emit_finding(g, "DLLHijack", "MEDIUM", finding, "Identify a privileged process that loads from this directory");
    }
    if (seen) HeapFree(GetProcessHeap(), 0, seen);
    if (machine_path) HeapFree(GetProcessHeap(), 0, machine_path);
    if (machine_raw) HeapFree(GetProcessHeap(), 0, machine_raw);
    HeapFree(GetProcessHeap(), 0, process_path);
}

void ph_collect_always_install_elevated(PH_GRAPH *g) {
    DWORD machine = 0, user = 0;
    const char *key = "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer";
    if (!g) return;
    if (ph_reg_dword(HKEY_LOCAL_MACHINE, key, "AlwaysInstallElevated", &machine) && machine == 1 &&
        ph_reg_dword(HKEY_CURRENT_USER, key, "AlwaysInstallElevated", &user) && user == 1) {
        char nid[33], props[2048], name[1024];
        PH_JSON p;
        ph_id(g, "regkey", "AIE", nid);
        ph_copy_local(name, sizeof(name), "ALWAYSINSTALLELEVATED@"); ph_append_local(name, sizeof(name), g->hostname);
        ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p);
        ph_json_add_string(&p, "name", name); ph_json_add_string(&p, "hostname", g->hostname); ph_json_end_object(&p);
        ph_emit_node(g, nid, "[\"PHRegistryMisconfig\"]", props);
        ph_emit_edge(g, g->current_user_id, nid, "PHCanExploit", "{\"mitre\":\"T1548.002\"}");
        ph_emit_empty_edge(g, nid, g->system_id, "PHEscalatesTo");
        ph_emit_finding(g, "AIE", "CRITICAL", "AlwaysInstallElevated enabled in HKLM and HKCU", "Install an authorized test MSI in the isolated lab to validate the policy");
    }
}

void ph_collect_uac(PH_GRAPH *g) {
    const char *key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
    DWORD enable_lua = 0, consent = 0, local_filter = 0;
    BOOL has_lua, has_consent, has_filter, in_admin_group;
    if (!g) return;
    has_lua = ph_reg_dword(HKEY_LOCAL_MACHINE, key, "EnableLUA", &enable_lua);
    has_consent = ph_reg_dword(HKEY_LOCAL_MACHINE, key, "ConsentPromptBehaviorAdmin", &consent);
    has_filter = ph_reg_dword(HKEY_LOCAL_MACHINE, key, "LocalAccountTokenFilterPolicy", &local_filter);
    in_admin_group = ph_token_has_admin_group();
    if (has_lua && enable_lua == 0) {
        char nid[33], props[2048], name[1024]; PH_JSON p;
        ph_id(g, "uac", "LUA_disabled", nid);
        ph_copy_local(name, sizeof(name), "UAC:DISABLED@"); ph_append_local(name, sizeof(name), g->hostname);
        ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p);
        ph_json_add_string(&p, "name", name); ph_json_add_string(&p, "hostname", g->hostname);
        ph_json_add_int(&p, "enableLUA", enable_lua); if (has_consent) ph_json_add_int(&p, "consentBehavior", consent);
        ph_json_end_object(&p); ph_emit_node(g, nid, "[\"PHUACBypass\"]", props);
        ph_emit_edge(g, g->current_user_id, nid, "PHCanBypassUAC", "{\"mitre\":\"T1548.002\"}");
        ph_emit_empty_edge(g, nid, g->admin_id, "PHEscalatesTo");
        ph_emit_finding(g, "UAC", "HIGH", "UAC is disabled (EnableLUA=0)", "All processes run elevated for administrator accounts");
    } else if (has_consent && consent == 0 && in_admin_group) {
        char nid[33], props[2048], name[1024]; PH_JSON p;
        ph_id(g, "uac", "NoPrompt", nid);
        ph_copy_local(name, sizeof(name), "UAC:NOPROMPT@"); ph_append_local(name, sizeof(name), g->hostname);
        ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p);
        ph_json_add_string(&p, "name", name); ph_json_add_string(&p, "hostname", g->hostname);
        if (has_lua) ph_json_add_int(&p, "enableLUA", enable_lua); ph_json_add_int(&p, "consentBehavior", consent);
        ph_json_end_object(&p); ph_emit_node(g, nid, "[\"PHUACBypass\"]", props);
        ph_emit_edge(g, g->current_user_id, nid, "PHCanBypassUAC", "{\"mitre\":\"T1548.002\"}");
        ph_emit_empty_edge(g, nid, g->admin_id, "PHEscalatesTo");
        ph_emit_finding(g, "UAC", "HIGH", "UAC is configured to never prompt administrators", "Validate elevation behavior in the isolated lab");
    } else if (in_admin_group && !g->is_admin) {
        ph_emit_finding(g, "UAC", "MEDIUM", "Administrator is running with a filtered token (normal UAC behavior; bypass unverified)", "Verify UAC policy before considering an elevation technique");
    }
    if (has_filter && local_filter == 1) {
        ph_emit_finding(g, "UAC", "MEDIUM", "LocalAccountTokenFilterPolicy=1 (remote administration via local accounts)", "Review whether remote local-account administration is required");
    }
}

void ph_collect(PH_GRAPH *graph) {
    if (!graph) return;
    ph_collect_core(graph);
    ph_collect_token_privileges(graph);
    ph_collect_services(graph);
    ph_collect_unquoted_service_paths(graph);
    ph_collect_writable_path(graph);
    ph_collect_always_install_elevated(graph);
    ph_collect_uac(graph);
}

