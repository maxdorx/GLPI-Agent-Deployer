#include "common.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cwctype>
#include <shlobj.h>
#include <sstream>

namespace fs = std::filesystem;

namespace mcd {

fs::path ModulePath() {
    std::wstring buffer(32768, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (length == 0 || length >= buffer.size()) ThrowLastError("GetModuleFileNameW");
    buffer.resize(length);
    return fs::path(buffer);
}

fs::path ModuleDirectory() { return ModulePath().parent_path(); }

fs::path ProgramDataDirectory() {
    PWSTR raw = nullptr;
    const HRESULT result = SHGetKnownFolderPath(FOLDERID_ProgramData, 0, nullptr, &raw);
    if (FAILED(result)) throw Error("Could not locate ProgramData.");
    fs::path path(raw);
    CoTaskMemFree(raw);
    return path / L"GLPI Agent Deployer";
}

std::string Utf8(const std::wstring& value) {
    if (value.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0) ThrowLastError("WideCharToMultiByte");
    std::string output(size, '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
        output.data(), size, nullptr, nullptr);
    return output;
}

std::wstring Wide(const std::string& value) {
    if (value.empty()) return {};
    const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0);
    if (size <= 0) ThrowLastError("MultiByteToWideChar");
    std::wstring output(size, L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), output.data(), size);
    return output;
}

std::wstring Win32Message(DWORD error) {
    wchar_t* raw = nullptr;
    const DWORD length = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, error, 0, reinterpret_cast<wchar_t*>(&raw), 0, nullptr);
    std::wstring text = length && raw ? std::wstring(raw, length) : L"Unknown Windows error";
    if (raw) LocalFree(raw);
    return Trim(text);
}

void ThrowLastError(const char* operation, DWORD error) {
    std::ostringstream message;
    message << operation << " failed with Windows error " << error << ": " << Utf8(Win32Message(error));
    throw Error(message.str());
}

std::wstring Trim(std::wstring value) {
    const auto notSpace = [](wchar_t c) { return !std::iswspace(c); };
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), notSpace));
    value.erase(std::find_if(value.rbegin(), value.rend(), notSpace).base(), value.end());
    if (value.size() >= 2 && value.front() == L'"' && value.back() == L'"')
        value = value.substr(1, value.size() - 2);
    return value;
}

std::vector<std::wstring> Split(const std::wstring& value, wchar_t delimiter) {
    std::vector<std::wstring> output;
    std::wistringstream stream(value);
    std::wstring item;
    while (std::getline(stream, item, delimiter)) {
        item = Trim(item);
        if (!item.empty()) output.push_back(item);
    }
    return output;
}

long long UnixNow() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

unsigned BackoffSeconds(unsigned attempts, unsigned baseSeconds, unsigned maximumSeconds, const std::wstring& key) {
    unsigned hash = 2166136261u;
    for (const wchar_t character : key) {
        hash ^= static_cast<unsigned>(std::towupper(character));
        hash *= 16777619u;
    }
    const unsigned exponent = std::min(attempts > 0 ? attempts - 1 : 0u, 20u);
    const double raw = std::min<double>(maximumSeconds, baseSeconds * std::pow(2.0, exponent));
    const double jitter = (static_cast<int>(hash % 2001u) - 1000) / 10000.0;
    return static_cast<unsigned>(std::min<double>(maximumSeconds,
        std::max<double>(baseSeconds, std::round(raw * (1.0 + jitter)))));
}

static std::wstring ReadIni(const fs::path& path, const wchar_t* section, const wchar_t* key, const wchar_t* fallback) {
    std::wstring buffer(32768, L'\0');
    const DWORD size = GetPrivateProfileStringW(section, key, fallback, buffer.data(),
        static_cast<DWORD>(buffer.size()), path.c_str());
    buffer.resize(size);
    return buffer;
}

static unsigned ReadUnsigned(const fs::path& path, const wchar_t* section, const wchar_t* key, unsigned fallback) {
    const auto value = ReadIni(path, section, key, std::to_wstring(fallback).c_str());
    try { return static_cast<unsigned>(std::stoul(value)); }
    catch (...) { return fallback; }
}

static fs::path Resolve(const fs::path& root, const std::wstring& value) {
    const fs::path candidate(value);
    return fs::absolute(candidate.is_absolute() ? candidate : root / candidate).lexically_normal();
}

Config LoadConfig(const fs::path& iniPath) {
    if (!fs::exists(iniPath)) throw Error("Configuration file does not exist: " + Utf8(iniPath.wstring()));
    const fs::path root = iniPath.parent_path();
    Config config;
    config.domainController = ReadIni(iniPath, L"ActiveDirectory", L"DomainController", L"");
    config.searchBases = Split(ReadIni(iniPath, L"ActiveDirectory", L"SearchBases", L""), L'|');
    config.agentMsiPath = Resolve(root, ReadIni(iniPath, L"Payload", L"AgentMsi", L"Payload\\GLPI-Agent.msi"));
    config.remoteRunnerPath = Resolve(root, ReadIni(iniPath, L"Payload", L"RemoteRunner", L"Tools\\GLPI.Agent.Deployer.RemoteRunner.exe"));
    config.databasePath = Resolve(root, ReadIni(iniPath, L"State", L"Database", (ProgramDataDirectory() / L"state.db").c_str()));
    const auto logValue = ReadIni(iniPath, L"Logging", L"File", L"");
    if (!logValue.empty()) config.logPath = Resolve(root, logValue);
    config.serverUrl = ReadIni(iniPath, L"GLPI", L"Server", L"");
    config.httpUser = ReadIni(iniPath, L"GLPI", L"HttpUser", L"");
    const auto secretValue = ReadIni(iniPath, L"GLPI", L"HttpSecretFile", L"");
    if (!secretValue.empty()) config.httpSecretPath = Resolve(root, secretValue);
    config.tag = ReadIni(iniPath, L"GLPI", L"Tag", L"");
    config.agentServiceNames = Split(ReadIni(iniPath, L"Payload", L"ServiceNames", L"glpi-agent"), L'|');
    config.discoveryMinutes = ReadUnsigned(iniPath, L"Schedule", L"DiscoveryMinutes", 15);
    config.installedRecheckHours = ReadUnsigned(iniPath, L"Schedule", L"InstalledRecheckHours", 24);
    config.staleDays = ReadUnsigned(iniPath, L"Schedule", L"ComputerStaleDays", 7);
    config.workerCount = std::clamp(ReadUnsigned(iniPath, L"Schedule", L"WorkerCount", 4), 1u, 32u);
    config.connectTimeoutSeconds = std::clamp(ReadUnsigned(iniPath, L"Network", L"ConnectTimeoutSeconds", 3), 1u, 60u);
    config.installTimeoutSeconds = std::clamp(ReadUnsigned(iniPath, L"Network", L"InstallTimeoutSeconds", 600), 30u, 1800u);
    config.retryBaseSeconds = std::max(ReadUnsigned(iniPath, L"Retry", L"BaseSeconds", 60), 10u);
    config.retryMaximumSeconds = std::max(ReadUnsigned(iniPath, L"Retry", L"MaximumSeconds", 21600), config.retryBaseSeconds);
    if (config.agentServiceNames.empty()) throw Error("At least one GLPI Agent service name is required.");
    if (config.serverUrl.empty()) throw Error("The GLPI server URL is required.");
    return config;
}

static void Put(const fs::path& path, const wchar_t* section, const wchar_t* key, const std::wstring& value) {
    if (!WritePrivateProfileStringW(section, key, value.c_str(), path.c_str())) ThrowLastError("WritePrivateProfileStringW");
}

void WriteConfig(const fs::path& path, const Config& config) {
    fs::create_directories(path.parent_path());
    Put(path, L"ActiveDirectory", L"DomainController", config.domainController);
    std::wstring bases;
    for (size_t i = 0; i < config.searchBases.size(); ++i) {
        if (i) bases += L"|";
        bases += config.searchBases[i];
    }
    Put(path, L"ActiveDirectory", L"SearchBases", bases);
    Put(path, L"Payload", L"AgentMsi", config.agentMsiPath.wstring());
    Put(path, L"Payload", L"RemoteRunner", config.remoteRunnerPath.wstring());
    std::wstring serviceNames;
    for (size_t i = 0; i < config.agentServiceNames.size(); ++i) {
        if (i) serviceNames += L"|";
        serviceNames += config.agentServiceNames[i];
    }
    Put(path, L"Payload", L"ServiceNames", serviceNames);
    Put(path, L"GLPI", L"Server", config.serverUrl);
    Put(path, L"GLPI", L"HttpUser", config.httpUser);
    Put(path, L"GLPI", L"HttpSecretFile", config.httpSecretPath.wstring());
    Put(path, L"GLPI", L"Tag", config.tag);
    Put(path, L"State", L"Database", config.databasePath.wstring());
    Put(path, L"Logging", L"File", config.logPath.wstring());
    Put(path, L"Schedule", L"DiscoveryMinutes", std::to_wstring(config.discoveryMinutes));
    Put(path, L"Schedule", L"InstalledRecheckHours", std::to_wstring(config.installedRecheckHours));
    Put(path, L"Schedule", L"ComputerStaleDays", std::to_wstring(config.staleDays));
    Put(path, L"Schedule", L"WorkerCount", std::to_wstring(config.workerCount));
    Put(path, L"Network", L"ConnectTimeoutSeconds", std::to_wstring(config.connectTimeoutSeconds));
    Put(path, L"Network", L"InstallTimeoutSeconds", std::to_wstring(config.installTimeoutSeconds));
    Put(path, L"Retry", L"BaseSeconds", std::to_wstring(config.retryBaseSeconds));
    Put(path, L"Retry", L"MaximumSeconds", std::to_wstring(config.retryMaximumSeconds));
}

} // namespace mcd
