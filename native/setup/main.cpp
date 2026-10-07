#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <aclapi.h>
#include <conio.h>
#include <lmcons.h>
#include <ntsecapi.h>
#include <shlobj.h>
#include <wincrypt.h>

#include "../common/common.h"
#include "resource.h"

#include <filesystem>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

fs::path KnownFolder(REFKNOWNFOLDERID id) {
    PWSTR raw = nullptr;
    if (FAILED(SHGetKnownFolderPath(id, 0, nullptr, &raw))) throw mcd::Error("Could not locate a Windows known folder.");
    fs::path path(raw); CoTaskMemFree(raw); return path;
}

bool IsAdministrator() {
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    PSID administrators = nullptr;
    BOOL member = FALSE;
    if (AllocateAndInitializeSid(&authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administrators)) {
        CheckTokenMembership(nullptr, administrators, &member);
        FreeSid(administrators);
    }
    return member != FALSE;
}

std::wstring Ask(const std::wstring& prompt, const std::wstring& fallback = L"") {
    std::wcout << prompt;
    if (!fallback.empty()) std::wcout << L" [" << fallback << L"]";
    std::wcout << L": ";
    std::wstring value; std::getline(std::wcin, value); value = mcd::Trim(value);
    return value.empty() ? fallback : value;
}

bool YesNo(const std::wstring& prompt, bool fallback) {
    while (true) {
        std::wstring answer = Ask(prompt + (fallback ? L" [Y/n]" : L" [y/N]"));
        if (answer.empty()) return fallback;
        if (_wcsicmp(answer.c_str(), L"y") == 0 || _wcsicmp(answer.c_str(), L"yes") == 0) return true;
        if (_wcsicmp(answer.c_str(), L"n") == 0 || _wcsicmp(answer.c_str(), L"no") == 0) return false;
        std::wcout << L"Please enter Y or N.\n";
    }
}

unsigned AskNumber(const std::wstring& prompt, unsigned fallback, unsigned minimum, unsigned maximum) {
    while (true) {
        std::wstring answer = Ask(prompt, std::to_wstring(fallback));
        try {
            unsigned value = static_cast<unsigned>(std::stoul(answer));
            if (value >= minimum && value <= maximum) return value;
        } catch (...) {}
        std::wcout << L"Enter a number from " << minimum << L" to " << maximum << L".\n";
    }
}

std::wstring Password(const std::wstring& prompt = L"Enter password") {
    std::wcout << prompt << L": ";
    std::wstring value;
    while (true) {
        wchar_t character = _getwch();
        if (character == L'\r') break;
        if (character == L'\b') {
            if (!value.empty()) { value.pop_back(); std::wcout << L"\b \b"; }
        } else if (character >= 32) { value.push_back(character); std::wcout << L'*'; }
    }
    std::wcout << L"\n";
    return value;
}

void ValidateCredentials(const std::wstring& account, const std::wstring& password) {
    std::wstring user = account;
    std::wstring domain;
    const auto slash = account.find(L'\\');
    if (slash != std::wstring::npos) {
        domain = account.substr(0, slash);
        user = account.substr(slash + 1);
    }
    HANDLE token = nullptr;
    if (!LogonUserW(user.c_str(), domain.empty() ? nullptr : domain.c_str(), password.c_str(), LOGON32_LOGON_NETWORK,
        LOGON32_PROVIDER_DEFAULT, &token)) mcd::ThrowLastError("LogonUserW");
    CloseHandle(token);
}

class SecureText {
public:
    explicit SecureText(std::wstring text) : value(std::move(text)) {}
    ~SecureText() { if (!value.empty()) SecureZeroMemory(value.data(), value.size() * sizeof(wchar_t)); }
    SecureText(const SecureText&) = delete;
    SecureText& operator=(const SecureText&) = delete;
    std::wstring value;
};

void SaveProtectedSecret(const fs::path& path, const std::wstring& secret) {
    static const wchar_t entropyText[] = L"GLPI Agent Deployer HTTP credential v1";
    DATA_BLOB input{static_cast<DWORD>(secret.size() * sizeof(wchar_t)),
        reinterpret_cast<BYTE*>(const_cast<wchar_t*>(secret.data()))};
    DATA_BLOB entropy{static_cast<DWORD>((_countof(entropyText) - 1) * sizeof(wchar_t)),
        reinterpret_cast<BYTE*>(const_cast<wchar_t*>(entropyText))};
    DATA_BLOB output{};
    if (!CryptProtectData(&input, L"GLPI Agent HTTP password", &entropy, nullptr, nullptr,
        CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN, &output))
        mcd::ThrowLastError("CryptProtectData");
    fs::path temporary = path.wstring() + L".new";
    HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_HIDDEN, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        SecureZeroMemory(output.pbData, output.cbData); LocalFree(output.pbData);
        mcd::ThrowLastError("CreateFileW HTTP secret");
    }
    DWORD written = 0;
    const BOOL ok = WriteFile(file, output.pbData, output.cbData, &written, nullptr);
    FlushFileBuffers(file); CloseHandle(file);
    SecureZeroMemory(output.pbData, output.cbData); LocalFree(output.pbData);
    if (!ok || written != output.cbData) mcd::ThrowLastError("WriteFile HTTP secret");
    if (!MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        mcd::ThrowLastError("MoveFileExW HTTP secret");
}

std::vector<BYTE> AccountSid(const std::wstring& account) {
    DWORD sidSize = 0, domainSize = 0; SID_NAME_USE use{};
    LookupAccountNameW(nullptr, account.c_str(), nullptr, &sidSize, nullptr, &domainSize, &use);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) mcd::ThrowLastError("LookupAccountNameW");
    std::vector<BYTE> sid(sidSize); std::wstring domain(domainSize, L'\0');
    if (!LookupAccountNameW(nullptr, account.c_str(), sid.data(), &sidSize, domain.data(), &domainSize, &use))
        mcd::ThrowLastError("LookupAccountNameW");
    return sid;
}

void GrantServiceLogon(const std::wstring& account) {
    auto sid = AccountSid(account);
    LSA_OBJECT_ATTRIBUTES attributes{}; attributes.Length = sizeof(attributes);
    LSA_HANDLE policy = nullptr;
    NTSTATUS status = LsaOpenPolicy(nullptr, &attributes, POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT, &policy);
    if (status != 0) mcd::ThrowLastError("LsaOpenPolicy", LsaNtStatusToWinError(status));
    std::wstring right = L"SeServiceLogonRight";
    LSA_UNICODE_STRING value{static_cast<USHORT>(right.size() * sizeof(wchar_t)),
        static_cast<USHORT>((right.size() + 1) * sizeof(wchar_t)), right.data()};
    status = LsaAddAccountRights(policy, sid.data(), &value, 1);
    LsaClose(policy);
    if (status != 0) mcd::ThrowLastError("LsaAddAccountRights", LsaNtStatusToWinError(status));
}

void GrantDirectory(const fs::path& path, const std::wstring& account, DWORD permissions) {
    PACL oldAcl = nullptr; PSECURITY_DESCRIPTOR descriptor = nullptr;
    DWORD error = GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
        nullptr, nullptr, &oldAcl, nullptr, &descriptor);
    if (error != ERROR_SUCCESS) mcd::ThrowLastError("GetNamedSecurityInfoW", error);
    EXPLICIT_ACCESSW access{};
    access.grfAccessPermissions = permissions;
    access.grfAccessMode = GRANT_ACCESS;
    access.grfInheritance = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;
    access.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    access.Trustee.TrusteeType = TRUSTEE_IS_USER;
    access.Trustee.ptstrName = const_cast<LPWSTR>(account.c_str());
    PACL newAcl = nullptr;
    error = SetEntriesInAclW(1, &access, oldAcl, &newAcl);
    if (error == ERROR_SUCCESS) error = SetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION, nullptr, nullptr, newAcl, nullptr);
    if (newAcl) LocalFree(newAcl);
    if (descriptor) LocalFree(descriptor);
    if (error != ERROR_SUCCESS) mcd::ThrowLastError("SetNamedSecurityInfoW", error);
}

void ProtectSecretFile(const fs::path& path, const std::wstring& account) {
    auto accountSid = AccountSid(account);
    std::vector<BYTE> systemSid(SECURITY_MAX_SID_SIZE), administratorsSid(SECURITY_MAX_SID_SIZE);
    DWORD systemSize = static_cast<DWORD>(systemSid.size());
    DWORD administratorsSize = static_cast<DWORD>(administratorsSid.size());
    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, systemSid.data(), &systemSize) ||
        !CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, administratorsSid.data(), &administratorsSize))
        mcd::ThrowLastError("CreateWellKnownSid");
    EXPLICIT_ACCESSW entries[3]{};
    PSID sids[] = {systemSid.data(), administratorsSid.data(), accountSid.data()};
    DWORD rights[] = {FILE_ALL_ACCESS, FILE_ALL_ACCESS, FILE_GENERIC_READ};
    for (size_t i = 0; i < _countof(entries); ++i) {
        entries[i].grfAccessPermissions = rights[i];
        entries[i].grfAccessMode = SET_ACCESS;
        entries[i].grfInheritance = NO_INHERITANCE;
        entries[i].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        entries[i].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        entries[i].Trustee.ptstrName = reinterpret_cast<LPWSTR>(sids[i]);
    }
    entries[2].Trustee.TrusteeType = TRUSTEE_IS_USER;
    PACL acl = nullptr;
    DWORD error = SetEntriesInAclW(_countof(entries), entries, nullptr, &acl);
    if (error == ERROR_SUCCESS) error = SetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, acl, nullptr);
    if (acl) LocalFree(acl);
    if (error != ERROR_SUCCESS) mcd::ThrowLastError("Protect GLPI HTTP secret", error);
}

void WriteResource(WORD id, const fs::path& destination) {
    HRSRC resource = FindResourceW(nullptr, MAKEINTRESOURCEW(id), RT_RCDATA);
    if (!resource) mcd::ThrowLastError("FindResourceW");
    HGLOBAL loaded = LoadResource(nullptr, resource);
    void* bytes = LockResource(loaded); DWORD size = SizeofResource(nullptr, resource);
    fs::path temporary = destination.wstring() + L".new";
    HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) mcd::ThrowLastError("CreateFileW");
    DWORD written = 0;
    BOOL ok = WriteFile(file, bytes, size, &written, nullptr);
    FlushFileBuffers(file); CloseHandle(file);
    if (!ok || written != size) mcd::ThrowLastError("WriteFile");
    if (!MoveFileExW(temporary.c_str(), destination.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        mcd::ThrowLastError("MoveFileExW");
}

void StopExistingService() {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) return;
    SC_HANDLE service = OpenServiceW(manager, mcd::kServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (service) {
        SERVICE_STATUS status{}; ControlService(service, SERVICE_CONTROL_STOP, &status);
        for (int i = 0; i < 30; ++i) {
            if (!QueryServiceStatus(service, &status) || status.dwCurrentState == SERVICE_STOPPED) break;
            Sleep(500);
        }
        CloseServiceHandle(service);
    }
    CloseServiceHandle(manager);
}

void ConfigureService(const fs::path& executable, const std::wstring& account, const std::wstring& password) {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
    if (!manager) mcd::ThrowLastError("OpenSCManagerW");
    std::wstring command = L"\"" + executable.wstring() + L"\"";
    SC_HANDLE service = CreateServiceW(manager, mcd::kServiceName, mcd::kDisplayName,
        SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE,
        SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, command.c_str(),
        nullptr, nullptr, nullptr, account.c_str(), password.c_str());
    if (!service && GetLastError() == ERROR_SERVICE_EXISTS) {
        service = OpenServiceW(manager, mcd::kServiceName,
            SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
        if (service && !ChangeServiceConfigW(service, SERVICE_NO_CHANGE, SERVICE_AUTO_START,
            SERVICE_NO_CHANGE, command.c_str(), nullptr, nullptr, nullptr, account.c_str(), password.c_str(),
            mcd::kDisplayName)) { CloseServiceHandle(service); service = nullptr; }
    }
    if (!service) { DWORD error = GetLastError(); CloseServiceHandle(manager); mcd::ThrowLastError("CreateService/ChangeServiceConfig", error); }
    SERVICE_DESCRIPTIONW description{const_cast<LPWSTR>(L"Discovers Active Directory computers and installs a configured GLPI Agent MSI using ADMIN$ and Windows SCM/RPC.")};
    ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, &description);
    SERVICE_DELAYED_AUTO_START_INFO delayed{TRUE};
    ChangeServiceConfig2W(service, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &delayed);
    SC_ACTION actions[] = {{SC_ACTION_RESTART, 60000}, {SC_ACTION_RESTART, 60000}, {SC_ACTION_RESTART, 300000}};
    SERVICE_FAILURE_ACTIONSW failures{}; failures.dwResetPeriod = 86400; failures.cActions = 3; failures.lpsaActions = actions;
    ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS, &failures);
    if (!StartServiceW(service, 0, nullptr) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
        DWORD error = GetLastError(); CloseServiceHandle(service); CloseServiceHandle(manager); mcd::ThrowLastError("StartServiceW", error);
    }
    CloseServiceHandle(service); CloseServiceHandle(manager);
}

void RegisterEventSource(const fs::path& serviceExecutable) {
    HKEY key = nullptr;
    const std::wstring path = L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\" + std::wstring(mcd::kServiceName);
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr, &key, nullptr) == ERROR_SUCCESS) {
        const auto text = serviceExecutable.wstring(); DWORD types = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE;
        RegSetValueExW(key, L"EventMessageFile", 0, REG_EXPAND_SZ, reinterpret_cast<const BYTE*>(text.c_str()),
            static_cast<DWORD>((text.size() + 1) * sizeof(wchar_t)));
        RegSetValueExW(key, L"TypesSupported", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&types), sizeof(types));
        RegCloseKey(key);
    }
}

void RegisterUninstall(const fs::path& setup, const fs::path& installDirectory) {
    HKEY key = nullptr;
    const wchar_t* subkey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\GLPIAgentDeployer";
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, subkey, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &key, nullptr) != ERROR_SUCCESS) return;
    const std::wstring display = mcd::kDisplayName;
    const std::wstring version = L"1.0.0";
    const std::wstring uninstall = L"\"" + setup.wstring() + L"\" --uninstall";
    auto put = [&](const wchar_t* name, const std::wstring& value) {
        RegSetValueExW(key, name, 0, REG_SZ, reinterpret_cast<const BYTE*>(value.c_str()), static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t)));
    };
    put(L"DisplayName", display); put(L"DisplayVersion", version); put(L"Publisher", L"GLPI Agent Deployer");
    put(L"InstallLocation", installDirectory.wstring()); put(L"UninstallString", uninstall);
    DWORD one = 1; RegSetValueExW(key, L"NoModify", 0, REG_DWORD, reinterpret_cast<BYTE*>(&one), sizeof(one));
    RegSetValueExW(key, L"NoRepair", 0, REG_DWORD, reinterpret_cast<BYTE*>(&one), sizeof(one));
    RegCloseKey(key);
}

void Uninstall() {
    if (!IsAdministrator()) throw mcd::Error("Run the uninstaller as Administrator.");
    StopExistingService();
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (manager) {
        SC_HANDLE service = OpenServiceW(manager, mcd::kServiceName, DELETE);
        if (service) { DeleteService(service); CloseServiceHandle(service); }
        CloseServiceHandle(manager);
    }
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\GLPIAgentDeployer");
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\GLPIAgentDeployer");
    fs::path install = KnownFolder(FOLDERID_ProgramFiles) / L"GLPI Agent Deployer";
    const fs::path self = mcd::ModulePath();
    if (fs::exists(install)) {
        std::error_code error;
        for (const auto& entry : fs::directory_iterator(install, error)) {
            if (!error && !fs::equivalent(entry.path(), self, error)) {
                error.clear();
                fs::remove_all(entry.path(), error);
            }
            error.clear();
        }
    }
    std::wcout << L"The service has been removed. Configuration, logs, and SQLite state were preserved in:\n  "
               << mcd::ProgramDataDirectory().wstring() << L"\n";
    if (self.parent_path() == install) MoveFileExW(self.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
    RemoveDirectoryW(install.c_str());
    MoveFileExW(install.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
}

void Install() {
    if (!IsAdministrator()) throw mcd::Error("Right-click this installer and select 'Run as administrator'.");
    std::wcout << L"Welcome to the GLPI Agent Deployer installation program.\n\n"
        L"This service discovers computer accounts in Active Directory and installs your configured\n"
        L"GLPI Agent MSI when a workstation becomes reachable.\n\n"
        L"Enter a regular domain service account (DOMAIN\\user). It needs read access to the selected\n"
        L"Active Directory OUs and local Administrator rights on every target workstation. Using a\n"
        L"Domain Admin account is not recommended. The password is stored only by Windows Service\n"
        L"Control Manager and is never written to the configuration, log, or SQLite database.\n\n";

    const std::wstring account = Ask(L"Enter full service account name (such as DOMAIN\\user)");
    if (account.empty()) throw mcd::Error("A service account is required.");
    SecureText password(Password());
    std::wcout << L"Checking credentials and granting 'Log on as a service' locally...\n";
    ValidateCredentials(account, password.value);
    GrantServiceLogon(account);

    fs::path agent;
    while (true) {
        agent = fs::absolute(fs::path(Ask(L"Enter the full path to your GLPI Agent x64 .msi"))).lexically_normal();
        if (fs::is_regular_file(agent) && _wcsicmp(agent.extension().c_str(), L".msi") == 0) break;
        std::wcout << L"That MSI file does not exist. Please try again.\n";
    }
    std::wstring serverUrl;
    while (serverUrl.empty()) {
        serverUrl = Ask(L"Enter the GLPI server URL (for example https://glpi.example.com/)");
        if (serverUrl.find_first_of(L"\r\n\"") != std::wstring::npos ||
            (serverUrl.rfind(L"https://", 0) != 0 && serverUrl.rfind(L"http://", 0) != 0)) {
            std::wcout << L"Enter a valid HTTP or HTTPS URL without quote characters.\n";
            serverUrl.clear();
        }
    }
    std::wstring tag;
    while (true) {
        tag = Ask(L"Optional GLPI asset tag (leave blank for none)");
        if (tag.find_first_of(L"\r\n\"") == std::wstring::npos) break;
        std::wcout << L"The tag cannot contain quote or newline characters.\n";
    }
    std::wstring httpUser;
    while (true) {
        httpUser = Ask(L"Optional GLPI HTTP username (leave blank if authentication is not used)");
        if (httpUser.find_first_of(L"\r\n\"") == std::wstring::npos) break;
        std::wcout << L"The HTTP username cannot contain quote or newline characters.\n";
    }
    SecureText httpPassword(L"");
    while (!httpUser.empty() && httpPassword.value.empty()) {
        httpPassword.value = Password(L"Enter GLPI HTTP password");
        if (httpPassword.value.empty()) std::wcout << L"The GLPI HTTP password cannot be empty when a username is configured.\n";
    }
    const std::wstring dc = Ask(L"Preferred domain controller (leave blank for automatic discovery)");
    std::vector<std::wstring> bases;
    if (!YesNo(L"Target the entire Active Directory domain?", true)) {
        std::wcout << L"Enter one or more OU distinguished names separated by semicolons. Searches include child OUs.\n"
            L"Example: OU=Workstations,DC=contoso,DC=com;OU=Laptops,DC=contoso,DC=com\n";
        while (bases.empty()) bases = mcd::Split(Ask(L"Target OU(s)"), L';');
    }
    const unsigned workers = AskNumber(L"Maximum simultaneous deployments", 4, 1, 32);
    const unsigned discovery = AskNumber(L"Active Directory discovery interval in minutes", 15, 1, 1440);
    fs::path logPath;
    if (YesNo(L"Enable simple plaintext troubleshooting log?", true))
        logPath = Ask(L"Log file path", (mcd::ProgramDataDirectory() / L"deployer.log").wstring());

    const fs::path install = KnownFolder(FOLDERID_ProgramFiles) / L"GLPI Agent Deployer";
    const fs::path data = mcd::ProgramDataDirectory();
    const fs::path payload = install / L"Payload";
    const fs::path tools = install / L"Tools";
    const fs::path httpSecret = data / L"glpi-http-secret.bin";
    StopExistingService();
    fs::create_directories(payload); fs::create_directories(tools); fs::create_directories(data);
    WriteResource(IDR_SERVICE, install / L"GLPI.Agent.Deployer.Service.exe");
    WriteResource(IDR_RUNNER, tools / L"GLPI.Agent.Deployer.RemoteRunner.exe");
    fs::copy_file(agent, payload / L"GLPI-Agent.msi", fs::copy_options::overwrite_existing);
    fs::copy_file(mcd::ModulePath(), install / L"GLPI-Agent-Deployer.exe", fs::copy_options::overwrite_existing);
    if (httpUser.empty()) {
        std::error_code ignored;
        fs::remove(httpSecret, ignored);
    } else {
        SaveProtectedSecret(httpSecret, httpPassword.value);
    }

    mcd::Config config;
    config.domainController = dc; config.searchBases = bases;
    config.agentMsiPath = payload / L"GLPI-Agent.msi";
    config.remoteRunnerPath = tools / L"GLPI.Agent.Deployer.RemoteRunner.exe";
    config.databasePath = data / L"state.db"; config.logPath = logPath;
    config.serverUrl = serverUrl; config.httpUser = httpUser; config.tag = tag;
    if (!httpUser.empty()) config.httpSecretPath = httpSecret;
    config.workerCount = workers; config.discoveryMinutes = discovery;
    mcd::WriteConfig(install / L"config.ini", config);
    GrantDirectory(install, account, GENERIC_READ | GENERIC_EXECUTE);
    GrantDirectory(data, account, FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE);
    if (!httpUser.empty()) ProtectSecretFile(httpSecret, account);
    RegisterEventSource(install / L"GLPI.Agent.Deployer.Service.exe");
    ConfigureService(install / L"GLPI.Agent.Deployer.Service.exe", account, password.value);
    RegisterUninstall(install / L"GLPI-Agent-Deployer.exe", install);
    std::wcout << L"\nInstallation complete. The GLPI Agent Deployer service is running.\n"
        L"GLPI Agent MSI: " << (payload / L"GLPI-Agent.msi").wstring() << L"\n"
        L"GLPI server: " << serverUrl << L"\n"
        L"GLPI HTTP authentication: " << (httpUser.empty() ? L"not configured" : L"configured") << L"\n"
        L"Target scope: " << (bases.empty() ? L"entire domain" : std::to_wstring(bases.size()) + L" OU search base(s)") << L"\n"
        L"SQLite state: " << config.databasePath.wstring() << L"\n";
    if (!logPath.empty()) std::wcout << L"Plaintext log: " << logPath.wstring() << L"\n";
    else std::wcout << L"Plaintext log: disabled\n";
    std::wcout << L"The domain controller itself is automatically excluded.\n";
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    SetConsoleOutputCP(CP_UTF8);
    bool uninstall = argc > 1 && _wcsicmp(argv[1], L"--uninstall") == 0;
    try { if (uninstall) Uninstall(); else Install(); }
    catch (const std::exception& ex) {
        std::wcerr << L"\nERROR: " << mcd::Wide(ex.what()) << L"\n";
        if (!uninstall) { std::wcout << L"Press Enter to close."; std::wcin.get(); }
        return 1;
    }
    if (!uninstall) { std::wcout << L"\nPress Enter to close."; std::wcin.get(); }
    return 0;
}
