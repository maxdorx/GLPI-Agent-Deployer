#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define SECURITY_WIN32
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ole2.h>
#include <oleauto.h>
#include <activeds.h>
#include <adshlp.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <lm.h>
#include <sddl.h>
#include <winsqlite/winsqlite3.h>
#include <wincrypt.h>
#include <msi.h>
#include <msiquery.h>

#include "../common/common.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <iomanip>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <thread>

namespace fs = std::filesystem;
using namespace std::chrono_literals;

namespace {

SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
SERVICE_STATUS g_status{};
HANDLE g_stopEvent = nullptr;
std::atomic_bool g_consoleStop = false;

struct Computer { std::wstring host; std::wstring dn; unsigned attempts = 0; };

class SecureText {
public:
    explicit SecureText(std::wstring text = {}) : value(std::move(text)) {}
    ~SecureText() { if (!value.empty()) SecureZeroMemory(value.data(), value.size() * sizeof(wchar_t)); }
    SecureText(const SecureText&) = delete;
    SecureText& operator=(const SecureText&) = delete;
    std::wstring value;
};

std::wstring Lower(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), towlower);
    return value;
}

std::wstring LoadProtectedSecret(const fs::path& path) {
    if (path.empty() || !fs::is_regular_file(path)) throw mcd::Error("The configured GLPI HTTP secret file is missing.");
    std::ifstream input(path, std::ios::binary);
    std::vector<BYTE> encrypted((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    if (encrypted.empty()) throw mcd::Error("The configured GLPI HTTP secret file is empty.");
    static const wchar_t entropyText[] = L"GLPI Agent Deployer HTTP credential v1";
    DATA_BLOB source{static_cast<DWORD>(encrypted.size()), encrypted.data()};
    DATA_BLOB entropy{static_cast<DWORD>((_countof(entropyText) - 1) * sizeof(wchar_t)),
        reinterpret_cast<BYTE*>(const_cast<wchar_t*>(entropyText))};
    DATA_BLOB clear{};
    if (!CryptUnprotectData(&source, nullptr, &entropy, nullptr, nullptr,
        CRYPTPROTECT_UI_FORBIDDEN, &clear)) mcd::ThrowLastError("CryptUnprotectData");
    if (clear.cbData % sizeof(wchar_t) != 0) {
        SecureZeroMemory(clear.pbData, clear.cbData); LocalFree(clear.pbData);
        throw mcd::Error("The GLPI HTTP secret has an invalid format.");
    }
    std::wstring result(reinterpret_cast<wchar_t*>(clear.pbData), clear.cbData / sizeof(wchar_t));
    SecureZeroMemory(clear.pbData, clear.cbData); LocalFree(clear.pbData);
    return result;
}

std::wstring Hex(const std::wstring& value) {
    static constexpr wchar_t digits[] = L"0123456789ABCDEF";
    const BYTE* bytes = reinterpret_cast<const BYTE*>(value.data());
    std::wstring result;
    result.reserve(value.size() * sizeof(wchar_t) * 2);
    for (size_t i = 0; i < value.size() * sizeof(wchar_t); ++i) {
        result += digits[bytes[i] >> 4];
        result += digits[bytes[i] & 15];
    }
    return result;
}

void ProtectStagingDirectory(const fs::path& path) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", SDDL_REVISION_1, &descriptor, nullptr))
        mcd::ThrowLastError("ConvertStringSecurityDescriptorToSecurityDescriptorW");
    PACL dacl = nullptr;
    BOOL present = FALSE, defaulted = FALSE;
    if (!GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted) || !present) {
        LocalFree(descriptor);
        mcd::ThrowLastError("GetSecurityDescriptorDacl");
    }
    DWORD error = SetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr, nullptr, dacl, nullptr);
    LocalFree(descriptor);
    if (error != ERROR_SUCCESS) mcd::ThrowLastError("SetNamedSecurityInfoW staging", error);
}

class Logger {
public:
    explicit Logger(fs::path path) : path_(std::move(path)) {}

    void Write(const wchar_t* level, const std::wstring& message) {
        std::lock_guard lock(mutex_);
        if (!path_.empty()) {
            std::error_code ec;
            fs::create_directories(path_.parent_path(), ec);
            if (fs::exists(path_, ec) && fs::file_size(path_, ec) >= 5ull * 1024 * 1024) {
                fs::path backup = path_.wstring() + L".1";
                fs::remove(backup, ec);
                fs::rename(path_, backup, ec);
            }
            SYSTEMTIME now{};
            GetLocalTime(&now);
            std::wofstream out(path_, std::ios::app);
            if (out) out << std::setfill(L'0') << std::setw(4) << now.wYear << L'-'
                << std::setw(2) << now.wMonth << L'-' << std::setw(2) << now.wDay << L' '
                << std::setw(2) << now.wHour << L':' << std::setw(2) << now.wMinute << L':'
                << std::setw(2) << now.wSecond << L" [" << level << L"] " << message << L"\n";
        }
        if (_wcsicmp(level, L"ERROR") == 0 || _wcsicmp(level, L"WARN") == 0) Event(level, message);
    }

private:
    void Event(const wchar_t* level, const std::wstring& message) {
        HANDLE source = RegisterEventSourceW(nullptr, mcd::kServiceName);
        if (!source) return;
        LPCWSTR strings[] = {message.c_str()};
        ReportEventW(source, _wcsicmp(level, L"ERROR") == 0 ? EVENTLOG_ERROR_TYPE : EVENTLOG_WARNING_TYPE,
            0, 1, nullptr, 1, 0, strings, nullptr);
        DeregisterEventSource(source);
    }
    fs::path path_;
    std::mutex mutex_;
};

class Database {
public:
    explicit Database(const fs::path& path) {
        fs::create_directories(path.parent_path());
        if (sqlite3_open16(path.c_str(), &db_) != SQLITE_OK) throw mcd::Error("Could not open SQLite state database.");
        Exec("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;"
             "CREATE TABLE IF NOT EXISTS computers("
             "host TEXT PRIMARY KEY COLLATE NOCASE,dn TEXT NOT NULL,last_seen INTEGER NOT NULL,"
             "next_attempt INTEGER NOT NULL DEFAULT 0,attempts INTEGER NOT NULL DEFAULT 0,"
             "status TEXT NOT NULL DEFAULT 'new',last_error TEXT,last_success INTEGER);"
             "CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);"
             "CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,time INTEGER NOT NULL,host TEXT,level TEXT,message TEXT);");
    }
    ~Database() { if (db_) sqlite3_close(db_); }

    void Discovered(const std::vector<Computer>& computers) {
        std::lock_guard lock(mutex_);
        ExecUnlocked("BEGIN IMMEDIATE;");
        sqlite3_stmt* statement = nullptr;
        Prepare("INSERT INTO computers(host,dn,last_seen) VALUES(?1,?2,?3) "
                "ON CONFLICT(host) DO UPDATE SET dn=excluded.dn,last_seen=excluded.last_seen;", &statement);
        for (const auto& c : computers) {
            sqlite3_bind_text16(statement, 1, c.host.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text16(statement, 2, c.dn.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(statement, 3, mcd::UnixNow());
            sqlite3_step(statement);
            sqlite3_reset(statement);
        }
        sqlite3_finalize(statement);
        ExecUnlocked("COMMIT;");
    }

    std::vector<Computer> Due(unsigned staleDays, unsigned limit) {
        std::lock_guard lock(mutex_);
        sqlite3_stmt* statement = nullptr;
        Prepare("SELECT host,dn,attempts FROM computers WHERE next_attempt<=?1 AND last_seen>=?2 "
                "ORDER BY next_attempt,last_seen DESC LIMIT ?3;", &statement);
        sqlite3_bind_int64(statement, 1, mcd::UnixNow());
        sqlite3_bind_int64(statement, 2, mcd::UnixNow() - static_cast<long long>(staleDays) * 86400);
        sqlite3_bind_int(statement, 3, static_cast<int>(limit));
        std::vector<Computer> result;
        while (sqlite3_step(statement) == SQLITE_ROW) {
            result.push_back({reinterpret_cast<const wchar_t*>(sqlite3_column_text16(statement, 0)),
                reinterpret_cast<const wchar_t*>(sqlite3_column_text16(statement, 1)),
                static_cast<unsigned>(sqlite3_column_int(statement, 2))});
        }
        sqlite3_finalize(statement);
        if (!result.empty()) {
            Prepare("UPDATE computers SET next_attempt=?2 WHERE host=?1;", &statement);
            for (const auto& c : result) {
                sqlite3_bind_text16(statement, 1, c.host.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_int64(statement, 2, mcd::UnixNow() + 300);
                sqlite3_step(statement); sqlite3_reset(statement);
            }
            sqlite3_finalize(statement);
        }
        return result;
    }

    void Complete(const Computer& computer, const std::wstring& status, const std::wstring& error,
                  long long nextAttempt, bool resetAttempts, bool success) {
        std::lock_guard lock(mutex_);
        sqlite3_stmt* statement = nullptr;
        Prepare("UPDATE computers SET status=?2,last_error=?3,next_attempt=?4,"
                "attempts=CASE WHEN ?5 THEN 0 ELSE attempts+1 END,"
                "last_success=CASE WHEN ?6 THEN ?7 ELSE last_success END WHERE host=?1;", &statement);
        sqlite3_bind_text16(statement, 1, computer.host.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text16(statement, 2, status.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text16(statement, 3, error.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(statement, 4, nextAttempt);
        sqlite3_bind_int(statement, 5, resetAttempts ? 1 : 0);
        sqlite3_bind_int(statement, 6, success ? 1 : 0);
        sqlite3_bind_int64(statement, 7, mcd::UnixNow());
        sqlite3_step(statement);
        sqlite3_finalize(statement);
        AddEventUnlocked(computer.host, error.empty() ? L"INFO" : L"WARN", status + (error.empty() ? L"" : L": " + error));
    }

    void Maintenance() {
        std::lock_guard lock(mutex_);
        ExecUnlocked("DELETE FROM events WHERE time < strftime('%s','now') - 2592000;"
                     "DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 10000);");
    }

    bool EnsureDesiredVersion(const std::wstring& version) {
        std::lock_guard lock(mutex_);
        sqlite3_stmt* statement = nullptr;
        Prepare("SELECT value FROM metadata WHERE key='desired_agent_version';", &statement);
        std::wstring current;
        if (sqlite3_step(statement) == SQLITE_ROW) {
            const auto* value = reinterpret_cast<const wchar_t*>(sqlite3_column_text16(statement, 0));
            if (value) current = value;
        }
        sqlite3_finalize(statement);
        if (_wcsicmp(current.c_str(), version.c_str()) == 0) return false;
        ExecUnlocked("BEGIN IMMEDIATE;");
        try {
            ExecUnlocked("UPDATE computers SET next_attempt=0;");
            Prepare("INSERT INTO metadata(key,value) VALUES('desired_agent_version',?1) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value;", &statement);
            sqlite3_bind_text16(statement, 1, version.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(statement) != SQLITE_DONE) {
                sqlite3_finalize(statement);
                throw mcd::Error(sqlite3_errmsg(db_));
            }
            sqlite3_finalize(statement);
            ExecUnlocked("COMMIT;");
        } catch (...) {
            ExecUnlocked("ROLLBACK;");
            throw;
        }
        return true;
    }

private:
    void Prepare(const char* sql, sqlite3_stmt** statement) {
        if (sqlite3_prepare_v2(db_, sql, -1, statement, nullptr) != SQLITE_OK) throw mcd::Error(sqlite3_errmsg(db_));
    }
    void Exec(const char* sql) { std::lock_guard lock(mutex_); ExecUnlocked(sql); }
    void ExecUnlocked(const char* sql) {
        char* error = nullptr;
        if (sqlite3_exec(db_, sql, nullptr, nullptr, &error) != SQLITE_OK) {
            std::string message = error ? error : "SQLite error";
            sqlite3_free(error);
            throw mcd::Error(message);
        }
    }
    void AddEventUnlocked(const std::wstring& host, const std::wstring& level, const std::wstring& message) {
        sqlite3_stmt* statement = nullptr;
        Prepare("INSERT INTO events(time,host,level,message) VALUES(?1,?2,?3,?4);", &statement);
        sqlite3_bind_int64(statement, 1, mcd::UnixNow());
        sqlite3_bind_text16(statement, 2, host.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text16(statement, 3, level.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text16(statement, 4, message.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(statement);
        sqlite3_finalize(statement);
    }
    sqlite3* db_ = nullptr;
    std::mutex mutex_;
};

std::wstring AdsString(IADs* object, const wchar_t* property) {
    VARIANT value{};
    VariantInit(&value);
    std::wstring result;
    if (SUCCEEDED(object->Get(const_cast<BSTR>(property), &value)) && value.vt == VT_BSTR && value.bstrVal)
        result = value.bstrVal;
    VariantClear(&value);
    return result;
}

std::wstring DefaultNamingContext(const std::wstring& dc) {
    std::wstring path = L"LDAP://" + (dc.empty() ? L"" : dc + L"/") + L"RootDSE";
    IADs* object = nullptr;
    HRESULT hr = ADsOpenObject(path.c_str(), nullptr, nullptr,
        ADS_SECURE_AUTHENTICATION | ADS_USE_SIGNING | ADS_USE_SEALING, IID_IADs, reinterpret_cast<void**>(&object));
    if (FAILED(hr)) throw mcd::Error("Could not bind to Active Directory RootDSE (HRESULT " + std::to_string(hr) + ").");
    std::wstring value = AdsString(object, L"defaultNamingContext");
    object->Release();
    if (value.empty()) throw mcd::Error("Active Directory did not return defaultNamingContext.");
    return value;
}

std::vector<Computer> Discover(const mcd::Config& config) {
    std::vector<std::wstring> bases = config.searchBases;
    if (bases.empty()) bases.push_back(DefaultNamingContext(config.domainController));
    std::map<std::wstring, Computer> unique;
    for (const auto& base : bases) {
        std::wstring path = L"LDAP://" + (config.domainController.empty() ? L"" : config.domainController + L"/") + base;
        IDirectorySearch* search = nullptr;
        HRESULT hr = ADsOpenObject(path.c_str(), nullptr, nullptr,
            ADS_SECURE_AUTHENTICATION | ADS_USE_SIGNING | ADS_USE_SEALING,
            IID_IDirectorySearch, reinterpret_cast<void**>(&search));
        if (FAILED(hr)) throw mcd::Error("Could not bind to LDAP search base: " + mcd::Utf8(base));

        ADS_SEARCHPREF_INFO preferences[2]{};
        preferences[0].dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
        preferences[0].vValue.dwType = ADSTYPE_INTEGER;
        preferences[0].vValue.Integer = 500;
        preferences[1].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
        preferences[1].vValue.dwType = ADSTYPE_INTEGER;
        preferences[1].vValue.Integer = ADS_SCOPE_SUBTREE;
        search->SetSearchPreference(preferences, 2);
        LPWSTR attributes[] = {const_cast<LPWSTR>(L"dNSHostName"), const_cast<LPWSTR>(L"name"), const_cast<LPWSTR>(L"distinguishedName")};
        ADS_SEARCH_HANDLE handle = nullptr;
        hr = search->ExecuteSearch(const_cast<LPWSTR>(
            L"(&(objectCategory=computer)(objectClass=computer)(operatingSystem=Windows*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"),
            attributes, 3, &handle);
        if (FAILED(hr)) { search->Release(); throw mcd::Error("Active Directory search failed."); }
        while ((hr = search->GetNextRow(handle)) != S_ADS_NOMORE_ROWS) {
            if (FAILED(hr)) break;
            std::wstring host, name, dn;
            for (DWORD i = 0; i < 3; ++i) {
                ADS_SEARCH_COLUMN column{};
                if (SUCCEEDED(search->GetColumn(handle, attributes[i], &column))) {
                    if (column.dwNumValues && column.pADsValues[0].CaseIgnoreString) {
                        const std::wstring value = column.pADsValues[0].CaseIgnoreString;
                        if (i == 0) host = value; else if (i == 1) name = value; else dn = value;
                    }
                    search->FreeColumn(&column);
                }
            }
            if (host.empty()) host = name;
            if (!host.empty()) unique.emplace(Lower(host), Computer{host, dn, 0});
        }
        search->CloseSearchHandle(handle);
        search->Release();
        if (FAILED(hr) && hr != S_ADS_NOMORE_ROWS) throw mcd::Error("Active Directory paging failed.");
    }

    wchar_t local[256]{};
    DWORD size = _countof(local);
    GetComputerNameExW(ComputerNameDnsHostname, local, &size);
    unique.erase(Lower(local));
    size = _countof(local);
    GetComputerNameExW(ComputerNameDnsFullyQualified, local, &size);
    unique.erase(Lower(local));
    std::vector<Computer> result;
    for (auto& [key, computer] : unique) result.push_back(std::move(computer));
    return result;
}

bool Port445(const std::wstring& host, unsigned timeoutSeconds) {
    ADDRINFOW hints{}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM; hints.ai_protocol = IPPROTO_TCP;
    ADDRINFOW* addresses = nullptr;
    if (GetAddrInfoW(host.c_str(), L"445", &hints, &addresses) != 0) return false;
    bool connected = false;
    for (auto address = addresses; address && !connected; address = address->ai_next) {
        SOCKET socket = WSASocketW(address->ai_family, address->ai_socktype, address->ai_protocol, nullptr, 0, 0);
        if (socket == INVALID_SOCKET) continue;
        u_long nonblocking = 1; ioctlsocket(socket, FIONBIO, &nonblocking);
        int result = connect(socket, address->ai_addr, static_cast<int>(address->ai_addrlen));
        if (result == 0 || WSAGetLastError() == WSAEWOULDBLOCK) {
            fd_set writes; FD_ZERO(&writes); FD_SET(socket, &writes);
            timeval timeout{static_cast<long>(timeoutSeconds), 0};
            if (select(0, nullptr, &writes, nullptr, &timeout) > 0) {
                int error = 0; int length = sizeof(error);
                getsockopt(socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &length);
                connected = error == 0;
            }
        }
        closesocket(socket);
    }
    FreeAddrInfoW(addresses);
    return connected;
}

class ScHandle {
public:
    explicit ScHandle(SC_HANDLE handle = nullptr) : handle_(handle) {}
    ~ScHandle() { if (handle_) CloseServiceHandle(handle_); }
    ScHandle(const ScHandle&) = delete;
    ScHandle& operator=(const ScHandle&) = delete;
    operator SC_HANDLE() const { return handle_; }
    bool valid() const { return handle_ != nullptr; }
private: SC_HANDLE handle_;
};

struct RemoteArtifacts {
    SC_HANDLE service = nullptr;
    fs::path staging;
    ~RemoteArtifacts() {
        if (service) {
            SERVICE_STATUS status{};
            ControlService(service, SERVICE_CONTROL_STOP, &status);
            DeleteService(service);
        }
        if (!staging.empty()) {
            std::error_code ignored;
            fs::remove_all(staging, ignored);
        }
    }
};

std::vector<BYTE> Sha256(const fs::path& path) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectSize = 0, hashSize = 0, actual = 0;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
        throw mcd::Error("BCryptOpenAlgorithmProvider failed.");
    if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectSize), sizeof(objectSize), &actual, 0) < 0 ||
        BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashSize), sizeof(hashSize), &actual, 0) < 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0); throw mcd::Error("BCryptGetProperty failed.");
    }
    std::vector<BYTE> object(objectSize), digest(hashSize), buffer(1024 * 1024);
    if (BCryptCreateHash(algorithm, &hash, object.data(), objectSize, nullptr, 0, 0) < 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0); throw mcd::Error("BCryptCreateHash failed.");
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) { BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(algorithm, 0); throw mcd::Error("Could not read file for SHA-256 verification."); }
    while (input) {
        input.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
        const auto count = input.gcount();
        if (count > 0 && BCryptHashData(hash, buffer.data(), static_cast<ULONG>(count), 0) < 0) {
            BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(algorithm, 0); throw mcd::Error("BCryptHashData failed.");
        }
    }
    if (BCryptFinishHash(hash, digest.data(), hashSize, 0) < 0) {
        BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(algorithm, 0); throw mcd::Error("BCryptFinishHash failed.");
    }
    BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(algorithm, 0);
    return digest;
}

bool AgentInstalled(SC_HANDLE manager, const std::vector<std::wstring>& serviceNames) {
    for (const auto& name : serviceNames) {
        ScHandle service(OpenServiceW(manager, name.c_str(), SERVICE_QUERY_STATUS));
        if (service.valid()) return true;
        if (GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST) mcd::ThrowLastError("OpenServiceW");
    }
    return false;
}

std::wstring GuidText() {
    GUID guid{}; CoCreateGuid(&guid);
    wchar_t text[40]{}; StringFromGUID2(guid, text, _countof(text));
    std::wstring result(text);
    result.erase(std::remove_if(result.begin(), result.end(), [](wchar_t c) { return c == L'{' || c == L'}' || c == L'-'; }), result.end());
    return result;
}

std::wstring AdminPath(const std::wstring& host) {
    SHARE_INFO_2* info = nullptr;
    const std::wstring server = L"\\\\" + host;
    NET_API_STATUS status = NetShareGetInfo(const_cast<LPWSTR>(server.c_str()),
        const_cast<LPWSTR>(L"ADMIN$"), 2, reinterpret_cast<LPBYTE*>(&info));
    if (status != NERR_Success) mcd::ThrowLastError("NetShareGetInfo", status);
    std::wstring path = info->shi2_path ? info->shi2_path : L"C:\\Windows";
    NetApiBufferFree(info);
    return path;
}

std::wstring ReadResult(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    std::string data((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    return mcd::Wide(data);
}

std::wstring LastMsiAction(const fs::path& path) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return {};
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0) { CloseHandle(file); return {}; }
    constexpr DWORD maximum = 64 * 1024;
    const DWORD count = static_cast<DWORD>(std::min<LONGLONG>(size.QuadPart, maximum));
    LARGE_INTEGER offset{}; offset.QuadPart = size.QuadPart - count;
    SetFilePointerEx(file, offset, nullptr, FILE_BEGIN);
    std::string bytes(count, '\0');
    DWORD read = 0;
    const BOOL ok = ReadFile(file, bytes.data(), count, &read, nullptr);
    CloseHandle(file);
    if (!ok || !read) return {};
    bytes.resize(read);
    const int wideSize = MultiByteToWideChar(CP_ACP, 0, bytes.data(), static_cast<int>(bytes.size()), nullptr, 0);
    if (wideSize <= 0) return {};
    std::wstring text(static_cast<size_t>(wideSize), L'\0');
    MultiByteToWideChar(CP_ACP, 0, bytes.data(), static_cast<int>(bytes.size()), text.data(), wideSize);
    auto lines = mcd::Split(text, L'\n');
    for (auto line = lines.rbegin(); line != lines.rend(); ++line) {
        if (line->find(L"Action start") != std::wstring::npos ||
            line->find(L"Action ended") != std::wstring::npos ||
            line->find(L"Return value 3") != std::wstring::npos ||
            line->find(L"MainEngineThread is returning") != std::wstring::npos) {
            std::wstring safe = mcd::Trim(*line);
            if (safe.size() > 300) safe.resize(300);
            return safe;
        }
    }
    return {};
}

std::wstring ReadMsiProperty(const fs::path& msi, const wchar_t* property) {
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

bool ParseVersion(const std::wstring& version, std::vector<unsigned long>& parts) {
    if (version.empty()) return false;
    size_t start = 0;
    while (start < version.size()) {
        size_t end = version.find(L'.', start);
        if (end == std::wstring::npos) end = version.size();
        if (end == start) return false;
        unsigned long value = 0;
        for (size_t i = start; i < end; ++i) {
            if (version[i] < L'0' || version[i] > L'9') return false;
            const unsigned digit = static_cast<unsigned>(version[i] - L'0');
            if (value > (ULONG_MAX - digit) / 10) return false;
            value = value * 10 + digit;
        }
        parts.push_back(value);
        start = end + 1;
    }
    return !parts.empty();
}

int CompareVersions(const std::wstring& installed, const std::wstring& desired, bool& valid) {
    std::vector<unsigned long> left, right;
    valid = ParseVersion(installed, left) && ParseVersion(desired, right);
    if (!valid) return 0;
    const size_t count = std::max(left.size(), right.size());
    left.resize(count, 0);
    right.resize(count, 0);
    for (size_t i = 0; i < count; ++i) {
        if (left[i] < right[i]) return -1;
        if (left[i] > right[i]) return 1;
    }
    return 0;
}

std::wstring StatusValue(const std::wstring& status, const std::wstring& key) {
    const std::wstring prefix = key + L"=";
    for (const auto& raw : mcd::Split(status, L'\n')) {
        const std::wstring line = mcd::Trim(raw);
        if (line.rfind(prefix, 0) == 0) return mcd::Trim(line.substr(prefix.size()));
    }
    return {};
}

std::wstring ProbeInstalledVersion(const Computer& computer, SC_HANDLE manager,
    const mcd::Config& config) {
    const std::wstring id = GuidText();
    const fs::path relative = fs::path(L"Temp") / L"GLPIAgentDeployer" / id;
    const fs::path remoteShare = fs::path(L"\\\\" + computer.host + L"\\ADMIN$") / relative;
    const fs::path remoteLocal = fs::path(AdminPath(computer.host)) / relative;
    fs::create_directories(remoteShare);
    ProtectStagingDirectory(remoteShare);
    RemoteArtifacts cleanup{};
    cleanup.staging = remoteShare;
    const fs::path runner = remoteShare / L"GLPI.Agent.Deployer.RemoteRunner.exe";
    if (!CopyFileW(config.remoteRunnerPath.c_str(), runner.c_str(), FALSE))
        mcd::ThrowLastError("CopyFileW version probe");
    if (Sha256(runner) != Sha256(config.remoteRunnerPath))
        throw mcd::Error("Staged version probe SHA-256 verification failed.");

    const std::wstring temporaryName = L"GLPIProbe_" + id.substr(0, 12);
    const std::wstring command = L"\"" + (remoteLocal / runner.filename()).wstring() +
        L"\" --service-name " + temporaryName + L" --probe";
    ScHandle remoteService(CreateServiceW(manager, temporaryName.c_str(), L"GLPI Agent version probe",
        SERVICE_START | SERVICE_QUERY_STATUS | DELETE | SERVICE_STOP,
        SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        command.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr));
    if (!remoteService.valid()) mcd::ThrowLastError("CreateServiceW version probe");
    cleanup.service = remoteService;
    if (!StartServiceW(remoteService, 0, nullptr)) mcd::ThrowLastError("StartServiceW version probe");

    SERVICE_STATUS_PROCESS status{};
    DWORD needed = 0;
    bool stopped = false;
    for (int i = 0; i < 30; ++i) {
        if (!QueryServiceStatusEx(remoteService, SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&status), sizeof(status), &needed))
            mcd::ThrowLastError("QueryServiceStatusEx version probe");
        if (status.dwCurrentState == SERVICE_STOPPED) { stopped = true; break; }
        std::this_thread::sleep_for(1s);
    }
    if (!stopped) throw mcd::Error("Remote GLPI version probe timed out.");
    const fs::path resultPath = remoteShare / L"result.txt";
    const fs::path statusPath = remoteShare / L"status.txt";
    const std::wstring result = fs::exists(resultPath) ? ReadResult(resultPath) : L"";
    if (result.find(L"exitCode=0") == std::wstring::npos)
        throw mcd::Error("Remote GLPI version probe failed: " + mcd::Utf8(result));
    if (!fs::exists(statusPath)) throw mcd::Error("Remote GLPI version probe produced no status.");
    return StatusValue(ReadResult(statusPath), L"installedVersion");
}

void Deploy(const Computer& computer, const mcd::Config& config, const std::wstring& httpPassword,
            const std::wstring& packageVersion,
            Database& db, Logger& log) {
    auto retry = [&](const std::wstring& status, const std::wstring& error) {
        unsigned delay = mcd::BackoffSeconds(computer.attempts + 1, config.retryBaseSeconds,
            config.retryMaximumSeconds, computer.host);
        db.Complete(computer, status, error, mcd::UnixNow() + delay, false, false);
        log.Write(L"WARN", computer.host + L": " + error + L"; retry in " + std::to_wstring(delay) + L" seconds");
    };
    try {
        if (!Port445(computer.host, config.connectTimeoutSeconds)) { retry(L"offline", L"TCP 445 is unreachable"); return; }
        const std::wstring server = L"\\\\" + computer.host;
        ScHandle manager(OpenSCManagerW(server.c_str(), nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE));
        if (!manager.valid()) mcd::ThrowLastError("OpenSCManagerW");
        const bool agentWasPresent = AgentInstalled(manager, config.agentServiceNames);
        bool upgrading = false;
        if (agentWasPresent) {
            const std::wstring installedVersion = ProbeInstalledVersion(computer, manager, config);
            if (installedVersion.empty()) {
                db.Complete(computer, L"installed", L"", mcd::UnixNow() + config.installedRecheckHours * 3600ll, true, true);
                log.Write(L"WARN", computer.host + L": GLPI Agent service exists but its registered version could not be read; no upgrade attempted");
                return;
            }
            bool validVersions = false;
            const int comparison = CompareVersions(installedVersion, packageVersion, validVersions);
            if (validVersions && comparison >= 0) {
                db.Complete(computer, L"installed", L"", mcd::UnixNow() + config.installedRecheckHours * 3600ll, true, true);
                log.Write(L"INFO", computer.host + L": GLPI Agent " + installedVersion +
                    (comparison == 0 ? L" matches" : L" is newer than") +
                    L" desired version " + packageVersion + L"; no action");
                return;
            }
            if (!validVersions && _wcsicmp(installedVersion.c_str(), packageVersion.c_str()) == 0) {
                db.Complete(computer, L"installed", L"", mcd::UnixNow() + config.installedRecheckHours * 3600ll, true, true);
                log.Write(L"INFO", computer.host + L": GLPI Agent version matches " + packageVersion + L"; no action");
                return;
            }
            upgrading = true;
            log.Write(L"INFO", computer.host + L": GLPI Agent " + installedVersion +
                (validVersions ? L" is older than desired version " : L" differs from desired version ") +
                packageVersion + L"; upgrade required");
        }

        const std::wstring id = GuidText();
        const fs::path shareRoot = L"\\\\" + computer.host + L"\\ADMIN$";
        const fs::path relative = fs::path(L"Temp") / L"GLPIAgentDeployer" / id;
        const fs::path remoteShare = shareRoot / relative;
        const fs::path remoteLocal = fs::path(AdminPath(computer.host)) / relative;
        fs::create_directories(remoteShare);
        ProtectStagingDirectory(remoteShare);
        RemoteArtifacts cleanup{};
        cleanup.staging = remoteShare;
        const fs::path agent = remoteShare / L"GLPI-Agent.msi";
        const fs::path runner = remoteShare / L"GLPI.Agent.Deployer.RemoteRunner.exe";
        const fs::path installIni = remoteShare / L"install.ini";
        SecureText stagedPassword(Hex(httpPassword));
        log.Write(L"INFO", computer.host + (upgrading
            ? L": copying newer GLPI Agent MSI through ADMIN$"
            : L": copying GLPI Agent MSI through ADMIN$"));
        if (!CopyFileW(config.agentMsiPath.c_str(), agent.c_str(), FALSE)) mcd::ThrowLastError("CopyFileW GLPI Agent MSI");
        if (!CopyFileW(config.remoteRunnerPath.c_str(), runner.c_str(), FALSE)) mcd::ThrowLastError("CopyFileW runner");
        if (!WritePrivateProfileStringW(L"Install", L"Server", config.serverUrl.c_str(), installIni.c_str()) ||
            !WritePrivateProfileStringW(L"Install", L"Tag", config.tag.c_str(), installIni.c_str()) ||
            !WritePrivateProfileStringW(L"Install", L"User", config.httpUser.c_str(), installIni.c_str()) ||
            !WritePrivateProfileStringW(L"Install", L"PasswordHex", stagedPassword.value.c_str(), installIni.c_str()))
            mcd::ThrowLastError("WritePrivateProfileStringW install.ini");
        if (Sha256(agent) != Sha256(config.agentMsiPath) || Sha256(runner) != Sha256(config.remoteRunnerPath))
            throw mcd::Error("Staged file SHA-256 verification failed.");

        const std::wstring temporaryName = L"GLPIDeploy_" + id.substr(0, 12);
        const std::wstring command = L"\"" + (remoteLocal / runner.filename()).wstring() + L"\" --service-name " + temporaryName;
        ScHandle remoteService(CreateServiceW(manager, temporaryName.c_str(), L"GLPI Agent deployment helper",
            SERVICE_START | SERVICE_QUERY_STATUS | DELETE | SERVICE_STOP,
            SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
            command.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr));
        if (!remoteService.valid()) mcd::ThrowLastError("CreateServiceW");
        cleanup.service = remoteService;
        const fs::path resultPath = remoteShare / L"result.txt";
        const fs::path statusPath = remoteShare / L"status.txt";
        const fs::path msiLogPath = remoteShare / L"glpi-agent-install.log";
        log.Write(L"INFO", computer.host + L": starting silent GLPI Agent MSI installation via remote SCM");
        if (!StartServiceW(remoteService, 0, nullptr)) mcd::ThrowLastError("StartServiceW");
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(config.installTimeoutSeconds);
        auto nextHeartbeat = std::chrono::steady_clock::now() + 30s;
        const auto startedAt = std::chrono::steady_clock::now();
        std::wstring lastHelperStatus;
        SERVICE_STATUS_PROCESS status{}; DWORD needed = 0;
        bool stopped = false;
        while (std::chrono::steady_clock::now() < deadline) {
            if (!QueryServiceStatusEx(remoteService, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status), &needed))
                mcd::ThrowLastError("QueryServiceStatusEx");
            if (status.dwCurrentState == SERVICE_STOPPED) { stopped = true; break; }
            if (fs::exists(statusPath)) {
                std::wstring helperStatus = ReadResult(statusPath);
                std::replace(helperStatus.begin(), helperStatus.end(), L'\r', L' ');
                std::replace(helperStatus.begin(), helperStatus.end(), L'\n', L' ');
                helperStatus = mcd::Trim(helperStatus);
                if (!helperStatus.empty() && helperStatus != lastHelperStatus) {
                    log.Write(L"INFO", computer.host + L": remote helper status " + helperStatus);
                    lastHelperStatus = std::move(helperStatus);
                }
            }
            if (std::chrono::steady_clock::now() >= nextHeartbeat) {
                const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now() - startedAt).count();
                const auto action = LastMsiAction(msiLogPath);
                log.Write(L"INFO", computer.host + L": GLPI MSI is still running (" +
                    std::to_wstring(elapsed) + L" seconds elapsed)" +
                    (action.empty() ? L"" : L"; last MSI action: " + action));
                nextHeartbeat += 30s;
            }
            std::this_thread::sleep_for(1s);
        }
        if (!stopped) {
            SERVICE_STATUS ignored{}; ControlService(remoteService, SERVICE_CONTROL_STOP, &ignored);
            for (int i = 0; i < 30; ++i) {
                if (!QueryServiceStatusEx(remoteService, SC_STATUS_PROCESS_INFO,
                    reinterpret_cast<LPBYTE>(&status), sizeof(status), &needed) ||
                    status.dwCurrentState == SERVICE_STOPPED) break;
                std::this_thread::sleep_for(1s);
            }
            const auto action = LastMsiAction(msiLogPath);
            throw mcd::Error("Remote installation timed out" +
                mcd::Utf8(action.empty() ? L"." : L"; last MSI action: " + action));
        }
        std::wstring result = fs::exists(resultPath) ? ReadResult(resultPath) : L"Remote helper did not create result.txt";
        if (result.find(L"exitCode=0") == std::wstring::npos) throw mcd::Error("GLPI Agent installer failed: " + mcd::Utf8(result));
        if (!AgentInstalled(manager, config.agentServiceNames)) throw mcd::Error("GLPI Agent service was not present after installation.");
        db.Complete(computer, L"installed", L"", mcd::UnixNow() + config.installedRecheckHours * 3600ll, true, true);
        log.Write(L"INFO", computer.host + (upgrading
            ? L": GLPI Agent upgraded to " + packageVersion + L" and verified"
            : L": GLPI Agent installed and verified"));
    } catch (const std::exception& ex) {
        retry(L"failed", mcd::Wide(ex.what()));
    }
}

void ReportStatus(DWORD state, DWORD error = NO_ERROR, DWORD hint = 0) {
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwWin32ExitCode = error;
    g_status.dwWaitHint = hint;
    g_status.dwControlsAccepted = state == SERVICE_START_PENDING ? 0 : SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    static DWORD checkpoint = 1;
    g_status.dwCheckPoint = (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING) ? checkpoint++ : 0;
    if (g_statusHandle) SetServiceStatus(g_statusHandle, &g_status);
}

bool StopRequested() {
    return g_consoleStop || (g_stopEvent && WaitForSingleObject(g_stopEvent, 0) == WAIT_OBJECT_0);
}

void Run() {
    HRESULT com = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(com)) throw mcd::Error("COM initialization failed.");
    WSADATA winsock{};
    if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) { CoUninitialize(); throw mcd::Error("Winsock initialization failed."); }
    try {
        const mcd::Config config = mcd::LoadConfig(mcd::ModuleDirectory() / L"config.ini");
        SecureText httpPassword(config.httpUser.empty() ? L"" : LoadProtectedSecret(config.httpSecretPath));
        Logger log(config.logPath);
        Database db(config.databasePath);
        if (!fs::exists(config.agentMsiPath)) throw mcd::Error("Configured GLPI Agent MSI does not exist.");
        if (!fs::exists(config.remoteRunnerPath)) throw mcd::Error("Remote runner does not exist.");
        const std::wstring packageVersion = ReadMsiProperty(config.agentMsiPath, L"ProductVersion");
        if (packageVersion.empty()) throw mcd::Error("Could not read ProductVersion from the configured GLPI Agent MSI.");
        const bool versionChanged = db.EnsureDesiredVersion(packageVersion);
        log.Write(L"INFO", L"GLPI Agent Deployer started; desired agent version " + packageVersion);
        if (versionChanged)
            log.Write(L"INFO", L"Configured MSI version changed; all discovered computers are due for a version check");
        long long nextDiscovery = 0;
        while (!StopRequested()) {
            const long long now = mcd::UnixNow();
            if (now >= nextDiscovery) {
                try {
                    auto computers = Discover(config);
                    db.Discovered(computers);
                    db.Maintenance();
                    log.Write(L"INFO", L"Active Directory discovery found " + std::to_wstring(computers.size()) + L" unique Windows computer objects");
                } catch (const std::exception& ex) {
                    log.Write(L"ERROR", L"Active Directory discovery failed: " + mcd::Wide(ex.what()));
                }
                nextDiscovery = now + static_cast<long long>(config.discoveryMinutes) * 60;
            }
            auto due = db.Due(config.staleDays, config.workerCount);
            std::vector<std::future<void>> tasks;
            for (const auto& computer : due)
                tasks.push_back(std::async(std::launch::async, [&config, &httpPassword, &packageVersion, &db, &log, computer] {
                    Deploy(computer, config, httpPassword.value, packageVersion, db, log);
                }));
            for (auto& task : tasks) task.get();
            for (int i = 0; i < 10 && !StopRequested(); ++i) std::this_thread::sleep_for(1s);
        }
        log.Write(L"INFO", L"GLPI Agent Deployer stopped");
    } catch (...) {
        WSACleanup(); CoUninitialize(); throw;
    }
    WSACleanup();
    CoUninitialize();
}

DWORD WINAPI Handler(DWORD control, DWORD, LPVOID, LPVOID) {
    if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN) {
        ReportStatus(SERVICE_STOP_PENDING, NO_ERROR, 15000);
        if (g_stopEvent) SetEvent(g_stopEvent);
        return NO_ERROR;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}

void WINAPI ServiceMain(DWORD, LPWSTR*) {
    g_statusHandle = RegisterServiceCtrlHandlerExW(mcd::kServiceName, Handler, nullptr);
    if (!g_statusHandle) return;
    ReportStatus(SERVICE_START_PENDING, NO_ERROR, 15000);
    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    ReportStatus(SERVICE_RUNNING);
    DWORD result = NO_ERROR;
    try { Run(); }
    catch (const std::exception& ex) {
        Logger({}).Write(L"ERROR", L"Service stopped unexpectedly: " + mcd::Wide(ex.what()));
        result = ERROR_SERVICE_SPECIFIC_ERROR;
    }
    ReportStatus(SERVICE_STOPPED, result);
    if (g_stopEvent) { CloseHandle(g_stopEvent); g_stopEvent = nullptr; }
}

BOOL WINAPI ConsoleHandler(DWORD control) {
    if (control == CTRL_C_EVENT || control == CTRL_BREAK_EVENT || control == CTRL_CLOSE_EVENT) {
        g_consoleStop = true; return TRUE;
    }
    return FALSE;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc > 1 && _wcsicmp(argv[1], L"--self-test") == 0) {
        bool valid = false;
        if (CompareVersions(L"1.9", L"1.10", valid) != -1 || !valid) return 1;
        if (CompareVersions(L"1.20", L"1.17", valid) != 1 || !valid) return 1;
        if (CompareVersions(L"1.17", L"1.17.0", valid) != 0 || !valid) return 1;
        CompareVersions(L"development", L"1.20", valid);
        return valid ? 1 : 0;
    }
    if (argc > 1 && _wcsicmp(argv[1], L"--console") == 0) {
        SetConsoleCtrlHandler(ConsoleHandler, TRUE);
        try { Run(); return 0; }
        catch (const std::exception& ex) { fwprintf(stderr, L"Error: %s\n", mcd::Wide(ex.what()).c_str()); return 1; }
    }
    SERVICE_TABLE_ENTRYW table[] = {{const_cast<LPWSTR>(mcd::kServiceName), ServiceMain}, {nullptr, nullptr}};
    if (!StartServiceCtrlDispatcherW(table)) return static_cast<int>(GetLastError());
    return 0;
}
