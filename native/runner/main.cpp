#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <msi.h>
#include <msiquery.h>

#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <vector>

namespace fs = std::filesystem;

static SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
static SERVICE_STATUS g_status{};
static std::wstring g_serviceName;
static std::mutex g_processMutex;
static HANDLE g_job = nullptr;
static HANDLE g_process = nullptr;
static bool g_probe = false;

static fs::path ModulePath() {
    std::wstring path(32768, L'\0');
    DWORD size = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    path.resize(size);
    return path;
}

static std::wstring ReadIni(const fs::path& path, const wchar_t* key) {
    std::wstring buffer(32768, L'\0');
    DWORD size = GetPrivateProfileStringW(L"Install", key, L"", buffer.data(),
        static_cast<DWORD>(buffer.size()), path.c_str());
    buffer.resize(size);
    return buffer;
}

class SecureText {
public:
    explicit SecureText(std::wstring text = {}) : value(std::move(text)) {}
    ~SecureText() { if (!value.empty()) SecureZeroMemory(value.data(), value.size() * sizeof(wchar_t)); }
    std::wstring value;
};

static int HexDigit(wchar_t value) {
    if (value >= L'0' && value <= L'9') return value - L'0';
    if (value >= L'A' && value <= L'F') return value - L'A' + 10;
    if (value >= L'a' && value <= L'f') return value - L'a' + 10;
    return -1;
}

static bool DecodeHex(const std::wstring& encoded, std::wstring& output) {
    if (encoded.size() % 2 != 0) return false;
    std::vector<BYTE> bytes(encoded.size() / 2);
    for (size_t i = 0; i < bytes.size(); ++i) {
        int high = HexDigit(encoded[i * 2]);
        int low = HexDigit(encoded[i * 2 + 1]);
        if (high < 0 || low < 0) {
            if (!bytes.empty()) SecureZeroMemory(bytes.data(), bytes.size());
            return false;
        }
        bytes[i] = static_cast<BYTE>((high << 4) | low);
    }
    if (bytes.size() % sizeof(wchar_t) != 0) {
        if (!bytes.empty()) SecureZeroMemory(bytes.data(), bytes.size());
        return false;
    }
    output.assign(reinterpret_cast<const wchar_t*>(bytes.data()), bytes.size() / sizeof(wchar_t));
    if (!bytes.empty()) SecureZeroMemory(bytes.data(), bytes.size());
    return true;
}

static std::wstring Quote(const std::wstring& value) {
    std::wstring result = L"\"";
    size_t slashes = 0;
    for (wchar_t c : value) {
        if (c == L'\\') { ++slashes; continue; }
        if (c == L'\"') {
            result.append(slashes * 2 + 1, L'\\');
            result += c; slashes = 0; continue;
        }
        result.append(slashes, L'\\'); slashes = 0; result += c;
    }
    result.append(slashes * 2, L'\\');
    result += L'\"';
    return result;
}

static std::wstring Property(const wchar_t* name, const std::wstring& value) {
    return std::wstring(name) + L"=" + Quote(value);
}

static std::wstring ReadMsiProperty(const fs::path& msi, const wchar_t* property) {
    MSIHANDLE database = 0;
    if (MsiOpenDatabaseW(msi.c_str(), MSIDBOPEN_READONLY, &database) != ERROR_SUCCESS) return {};
    const std::wstring query = L"SELECT `Value` FROM `Property` WHERE `Property`='" +
        std::wstring(property) + L"'";
    MSIHANDLE view = 0;
    if (MsiDatabaseOpenViewW(database, query.c_str(), &view) != ERROR_SUCCESS) {
        MsiCloseHandle(database);
        return {};
    }
    std::wstring value;
    if (MsiViewExecute(view, 0) == ERROR_SUCCESS) {
        MSIHANDLE record = 0;
        if (MsiViewFetch(view, &record) == ERROR_SUCCESS) {
            DWORD size = 0;
            wchar_t dummy = L'\0';
            if (MsiRecordGetStringW(record, 1, &dummy, &size) == ERROR_MORE_DATA) {
                value.resize(static_cast<size_t>(size) + 1);
                DWORD capacity = size + 1;
                if (MsiRecordGetStringW(record, 1, value.data(), &capacity) == ERROR_SUCCESS)
                    value.resize(capacity);
                else
                    value.clear();
            }
            MsiCloseHandle(record);
        }
    }
    MsiViewClose(view);
    MsiCloseHandle(view);
    MsiCloseHandle(database);
    return value;
}

static std::wstring ReadInstalledVersion(REGSAM view) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\GLPI-Agent\\Installer", 0,
        KEY_QUERY_VALUE | view, &key) != ERROR_SUCCESS) return {};
    DWORD type = 0;
    DWORD bytes = 0;
    LONG result = RegQueryValueExW(key, L"Version", nullptr, &type, nullptr, &bytes);
    std::wstring value;
    if (result == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ) && bytes >= sizeof(wchar_t)) {
        value.resize(bytes / sizeof(wchar_t));
        result = RegQueryValueExW(key, L"Version", nullptr, &type,
            reinterpret_cast<LPBYTE>(value.data()), &bytes);
        if (result == ERROR_SUCCESS) {
            while (!value.empty() && value.back() == L'\0') value.pop_back();
        } else {
            value.clear();
        }
    }
    RegCloseKey(key);
    return value;
}

static bool ShouldRepair(const std::wstring& installedVersion, const std::wstring& packageVersion) {
    return !installedVersion.empty() && !packageVersion.empty() &&
        _wcsicmp(installedVersion.c_str(), packageVersion.c_str()) == 0;
}

static void WriteStatus(const fs::path& directory, const std::wstring& mode,
    const std::wstring& installedVersion, const std::wstring& packageVersion,
    const char* phase = nullptr) {
    std::ofstream output(directory / L"status.txt", std::ios::binary | std::ios::trunc);
    output << "mode=";
    if (mode == L"repair") output << "repair";
    else if (mode == L"probe") output << "probe";
    else output << "install-or-upgrade";
    auto writeVersion = [&](const char* name, const std::wstring& value) {
        if (value.empty()) return;
        int bytes = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
            nullptr, 0, nullptr, nullptr);
        std::string utf8(static_cast<size_t>(bytes), '\0');
        if (bytes) WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
            utf8.data(), bytes, nullptr, nullptr);
        output << "\r\n" << name << "=" << utf8;
    };
    writeVersion("installedVersion", installedVersion);
    writeVersion("packageVersion", packageVersion);
    if (phase && *phase) output << "\r\nphase=" << phase;
    output << "\r\n";
}

static void Report(DWORD state, DWORD error = NO_ERROR, DWORD hint = 0) {
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwWin32ExitCode = error;
    g_status.dwServiceSpecificExitCode = error == ERROR_SERVICE_SPECIFIC_ERROR ? 1 : 0;
    g_status.dwWaitHint = hint;
    g_status.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP : 0;
    static DWORD checkpoint = 1;
    g_status.dwCheckPoint = state == SERVICE_START_PENDING ? checkpoint++ : 0;
    if (g_statusHandle) SetServiceStatus(g_statusHandle, &g_status);
}

static void WriteResult(DWORD normalizedExitCode, DWORD installerExitCode, DWORD error, const std::wstring& message) {
    const fs::path finalPath = ModulePath().parent_path() / L"result.txt";
    const fs::path temporary = finalPath.wstring() + L".tmp";
    std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
    output << "exitCode=" << normalizedExitCode << "\r\ninstallerExitCode=" << installerExitCode
           << "\r\nerror=" << error << "\r\n";
    if (!message.empty()) {
        int bytes = WideCharToMultiByte(CP_UTF8, 0, message.data(), static_cast<int>(message.size()), nullptr, 0, nullptr, nullptr);
        std::string utf8(static_cast<size_t>(bytes), '\0');
        if (bytes) WideCharToMultiByte(CP_UTF8, 0, message.data(), static_cast<int>(message.size()), utf8.data(), bytes, nullptr, nullptr);
        output << "message=" << utf8 << "\r\n";
    }
    output.close();
    MoveFileExW(temporary.c_str(), finalPath.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
}

static bool StopExistingAgent(bool& wasRunning, DWORD& error) {
    wasRunning = false;
    error = NO_ERROR;
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) { error = GetLastError(); return false; }
    SC_HANDLE service = OpenServiceW(manager, L"glpi-agent", SERVICE_QUERY_STATUS | SERVICE_STOP | SERVICE_START);
    if (!service) {
        error = GetLastError();
        CloseServiceHandle(manager);
        if (error == ERROR_SERVICE_DOES_NOT_EXIST) { error = NO_ERROR; return true; }
        return false;
    }
    SERVICE_STATUS_PROCESS status{};
    DWORD needed = 0;
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&status), sizeof(status), &needed)) {
        error = GetLastError();
        CloseServiceHandle(service); CloseServiceHandle(manager);
        return false;
    }
    wasRunning = status.dwCurrentState != SERVICE_STOPPED;
    if (wasRunning && status.dwCurrentState != SERVICE_STOP_PENDING) {
        SERVICE_STATUS ignored{};
        if (!ControlService(service, SERVICE_CONTROL_STOP, &ignored) &&
            GetLastError() != ERROR_SERVICE_NOT_ACTIVE) {
            error = GetLastError();
            CloseServiceHandle(service); CloseServiceHandle(manager);
            return false;
        }
    }
    for (int i = 0; i < 60; ++i) {
        if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&status), sizeof(status), &needed)) {
            error = GetLastError(); break;
        }
        if (status.dwCurrentState == SERVICE_STOPPED) {
            CloseServiceHandle(service); CloseServiceHandle(manager);
            return true;
        }
        Sleep(1000);
    }
    if (error == NO_ERROR) error = ERROR_SERVICE_REQUEST_TIMEOUT;
    CloseServiceHandle(service); CloseServiceHandle(manager);
    return false;
}

static void RestartExistingAgentBestEffort(bool wasRunning) {
    if (!wasRunning) return;
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) return;
    SC_HANDLE service = OpenServiceW(manager, L"glpi-agent", SERVICE_START);
    if (service) { StartServiceW(service, 0, nullptr); CloseServiceHandle(service); }
    CloseServiceHandle(manager);
}

static bool WaitForWindowsInstaller(DWORD& error) {
    error = NO_ERROR;
    for (int i = 0; i < 120; ++i) {
        HANDLE mutex = OpenMutexW(SYNCHRONIZE | MUTEX_MODIFY_STATE, FALSE, L"Global\\_MSIExecute");
        if (!mutex && GetLastError() == ERROR_FILE_NOT_FOUND)
            mutex = OpenMutexW(SYNCHRONIZE | MUTEX_MODIFY_STATE, FALSE, L"_MSIExecute");
        if (!mutex) {
            const DWORD openError = GetLastError();
            if (openError == ERROR_FILE_NOT_FOUND) return true;
            error = openError;
            return false;
        }
        const DWORD wait = WaitForSingleObject(mutex, 1000);
        if (wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED) {
            ReleaseMutex(mutex);
            CloseHandle(mutex);
            return true;
        }
        CloseHandle(mutex);
        if (wait == WAIT_FAILED) { error = GetLastError(); return false; }
    }
    if (error == NO_ERROR) error = ERROR_INSTALL_ALREADY_RUNNING;
    return false;
}

static DWORD LaunchInstallerProcess(const fs::path& msiexec, const std::wstring& command,
    const fs::path& directory, DWORD& createError) {
    SecureText commandLine(command);
    STARTUPINFOW startup{}; startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(msiexec.c_str(), commandLine.value.data(), nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW, nullptr, directory.c_str(), &startup, &process)) {
        createError = GetLastError();
        return createError;
    }
    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    if (job) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits));
        AssignProcessToJobObject(job, process.hProcess);
    }
    {
        std::lock_guard lock(g_processMutex);
        g_job = job;
        g_process = process.hProcess;
    }
    WaitForSingleObject(process.hProcess, INFINITE);
    DWORD exitCode = ERROR_GEN_FAILURE;
    GetExitCodeProcess(process.hProcess, &exitCode);
    {
        std::lock_guard lock(g_processMutex);
        g_job = nullptr;
        g_process = nullptr;
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        if (job) CloseHandle(job);
    }
    createError = NO_ERROR;
    return exitCode;
}

static DWORD RunInstaller() {
    const fs::path directory = ModulePath().parent_path();
    const fs::path msi = directory / L"GLPI-Agent.msi";
    const fs::path ini = directory / L"install.ini";
    const fs::path msiLog = directory / L"glpi-agent-install.log";
    const std::wstring server = ReadIni(ini, L"Server");
    const std::wstring tag = ReadIni(ini, L"Tag");
    const std::wstring user = ReadIni(ini, L"User");
    SecureText password;
    SecureText passwordHex(ReadIni(ini, L"PasswordHex"));
    if (!DecodeHex(passwordHex.value, password.value)) {
        WriteResult(ERROR_INVALID_DATA, ERROR_INVALID_DATA, ERROR_INVALID_DATA,
            L"The staged GLPI HTTP credential has an invalid format.");
        return ERROR_INVALID_DATA;
    }
    if (!fs::exists(msi) || server.empty()) {
        WriteResult(ERROR_INVALID_DATA, ERROR_INVALID_DATA, ERROR_INVALID_DATA,
            L"GLPI-Agent.msi or the GLPI server URL is missing.");
        return ERROR_INVALID_DATA;
    }

    std::wstring installedVersion = ReadInstalledVersion(KEY_WOW64_64KEY);
    if (installedVersion.empty()) installedVersion = ReadInstalledVersion(KEY_WOW64_32KEY);
    const std::wstring packageVersion = ReadMsiProperty(msi, L"ProductVersion");
    const bool repair = ShouldRepair(installedVersion, packageVersion);
    const bool upgrade = !installedVersion.empty() && !packageVersion.empty() && !repair;
    WriteStatus(directory, repair ? L"repair" : L"install", installedVersion, packageVersion, "preparing");

    bool agentWasRunning = false;
    if (upgrade) {
        WriteStatus(directory, L"install", installedVersion, packageVersion, "stopping-existing-agent");
        DWORD stopError = NO_ERROR;
        if (!StopExistingAgent(agentWasRunning, stopError)) {
            RestartExistingAgentBestEffort(agentWasRunning);
            WriteResult(stopError, stopError, stopError,
                L"The existing GLPI Agent service could not be stopped for upgrade.");
            return stopError;
        }
    }

    WriteStatus(directory, repair ? L"repair" : L"install", installedVersion, packageVersion,
        "waiting-windows-installer");
    DWORD availabilityError = NO_ERROR;
    if (!WaitForWindowsInstaller(availabilityError)) {
        RestartExistingAgentBestEffort(agentWasRunning);
        WriteResult(availabilityError, ERROR_INSTALL_ALREADY_RUNNING, availabilityError,
            L"Windows Installer remained busy for two minutes.");
        return availabilityError;
    }

    wchar_t systemDirectory[MAX_PATH]{};
    if (!GetSystemDirectoryW(systemDirectory, _countof(systemDirectory))) {
        DWORD error = GetLastError(); WriteResult(error, error, error, L"GetSystemDirectoryW failed."); return error;
    }
    const fs::path msiexec = fs::path(systemDirectory) / L"msiexec.exe";
    SecureText command(Quote(msiexec.wstring()) + (repair ? L" /fa " : L" /i ") + Quote(msi.wstring()) +
        L" " + Property(L"SERVER", server));
    if (!tag.empty()) command.value += L" " + Property(L"TAG", tag);
    if (!user.empty()) {
        command.value += L" " + Property(L"USER", user);
        command.value += L" " + Property(L"PASSWORD", password.value);
    }
    command.value += L" RUNNOW=1 EXECMODE=1 ADDLOCAL=feat_AGENT,feat_DEPLOY,feat_COLLECT"
        L" TASK_FREQUENCY=hourly TASK_HOURLY_MODIFIER=1 /quiet /qn /norestart /L*v " + Quote(msiLog.wstring());

    DWORD installerExit = ERROR_GEN_FAILURE;
    DWORD createError = NO_ERROR;
    for (int attempt = 1; attempt <= 3; ++attempt) {
        const std::string phase = "running-msi-attempt-" + std::to_string(attempt);
        WriteStatus(directory, repair ? L"repair" : L"install", installedVersion, packageVersion, phase.c_str());
        installerExit = LaunchInstallerProcess(msiexec, command.value, directory, createError);
        if (createError != NO_ERROR) {
            RestartExistingAgentBestEffort(agentWasRunning);
            WriteResult(createError, createError, createError, L"Could not start Windows Installer.");
            return createError;
        }
        if (installerExit != ERROR_INSTALL_ALREADY_RUNNING || attempt == 3) break;
        Sleep(30000);
        WriteStatus(directory, repair ? L"repair" : L"install", installedVersion, packageVersion,
            "waiting-windows-installer");
        if (!WaitForWindowsInstaller(availabilityError)) break;
    }
    const bool success = installerExit == ERROR_SUCCESS || installerExit == ERROR_SUCCESS_REBOOT_INITIATED || installerExit == ERROR_SUCCESS_REBOOT_REQUIRED;
    if (!success) RestartExistingAgentBestEffort(agentWasRunning);
    WriteResult(success ? 0 : installerExit, installerExit, NO_ERROR,
        success ? (repair ? L"GLPI Agent MSI repair completed."
                          : (upgrade ? L"GLPI Agent MSI upgrade completed." : L"GLPI Agent MSI installation completed."))
                : L"Windows Installer returned a failure code.");
    return success ? ERROR_SUCCESS : installerExit;
}

static DWORD RunProbe() {
    const fs::path directory = ModulePath().parent_path();
    std::wstring installedVersion = ReadInstalledVersion(KEY_WOW64_64KEY);
    if (installedVersion.empty()) installedVersion = ReadInstalledVersion(KEY_WOW64_32KEY);
    WriteStatus(directory, L"probe", installedVersion, L"");
    WriteResult(ERROR_SUCCESS, ERROR_SUCCESS, NO_ERROR,
        installedVersion.empty() ? L"GLPI Agent installer version was not registered."
                                 : L"GLPI Agent installer version probe completed.");
    return ERROR_SUCCESS;
}

static DWORD WINAPI Handler(DWORD control, DWORD, LPVOID, LPVOID) {
    if (control != SERVICE_CONTROL_STOP) return ERROR_CALL_NOT_IMPLEMENTED;
    Report(SERVICE_STOP_PENDING, NO_ERROR, 15000);
    std::lock_guard lock(g_processMutex);
    if (g_job) TerminateJobObject(g_job, ERROR_TIMEOUT);
    else if (g_process) TerminateProcess(g_process, ERROR_TIMEOUT);
    return NO_ERROR;
}

static void WINAPI ServiceMain(DWORD, LPWSTR*) {
    g_statusHandle = RegisterServiceCtrlHandlerExW(g_serviceName.c_str(), Handler, nullptr);
    if (!g_statusHandle) return;
    Report(SERVICE_START_PENDING, NO_ERROR, 300000);
    Report(SERVICE_RUNNING);
    DWORD result = g_probe ? RunProbe() : RunInstaller();
    Report(SERVICE_STOPPED, result == 0 ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR);
}

int wmain(int argc, wchar_t** argv) {
    bool once = false;
    for (int i = 1; i < argc; ++i) {
        if (_wcsicmp(argv[i], L"--run-once") == 0) once = true;
        else if (_wcsicmp(argv[i], L"--probe") == 0) g_probe = true;
        else if (_wcsicmp(argv[i], L"--self-test") == 0) {
            return ShouldRepair(L"1.17", L"1.17") &&
                !ShouldRepair(L"1.16", L"1.17") &&
                !ShouldRepair(L"", L"1.17") &&
                !ShouldRepair(L"1.17", L"") &&
                Property(L"SERVER", L"https://inventory.example/") ==
                    L"SERVER=\"https://inventory.example/\"" ? 0 : 1;
        }
        else if (_wcsicmp(argv[i], L"--service-name") == 0 && i + 1 < argc) g_serviceName = argv[++i];
    }
    if (once) return static_cast<int>(g_probe ? RunProbe() : RunInstaller());
    if (g_serviceName.empty()) return ERROR_INVALID_PARAMETER;
    SERVICE_TABLE_ENTRYW table[] = {{g_serviceName.data(), ServiceMain}, {nullptr, nullptr}};
    if (!StartServiceCtrlDispatcherW(table)) return static_cast<int>(GetLastError());
    return 0;
}
