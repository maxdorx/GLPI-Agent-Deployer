#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>

namespace mcd {

inline constexpr wchar_t kServiceName[] = L"GLPIAgentDeployer";
inline constexpr wchar_t kDisplayName[] = L"GLPI Agent Deployer";

struct Config {
    std::wstring domainController;
    std::vector<std::wstring> searchBases;
    std::filesystem::path agentMsiPath;
    std::filesystem::path remoteRunnerPath;
    std::filesystem::path databasePath;
    std::filesystem::path logPath;
    std::filesystem::path httpSecretPath;
    std::wstring serverUrl;
    std::wstring httpUser;
    std::wstring tag;
    std::vector<std::wstring> agentServiceNames{L"glpi-agent"};
    unsigned discoveryMinutes = 15;
    unsigned installedRecheckHours = 24;
    unsigned staleDays = 7;
    unsigned workerCount = 4;
    unsigned connectTimeoutSeconds = 3;
    unsigned installTimeoutSeconds = 600;
    unsigned retryBaseSeconds = 60;
    unsigned retryMaximumSeconds = 21600;
};

class Error : public std::runtime_error {
public:
    explicit Error(const std::string& message) : std::runtime_error(message) {}
};

std::filesystem::path ModulePath();
std::filesystem::path ModuleDirectory();
std::filesystem::path ProgramDataDirectory();
std::string Utf8(const std::wstring& value);
std::wstring Wide(const std::string& value);
std::wstring Win32Message(DWORD error);
std::wstring Trim(std::wstring value);
std::vector<std::wstring> Split(const std::wstring& value, wchar_t delimiter);
long long UnixNow();
unsigned BackoffSeconds(unsigned attempts, unsigned baseSeconds, unsigned maximumSeconds, const std::wstring& key);
Config LoadConfig(const std::filesystem::path& iniPath);
void WriteConfig(const std::filesystem::path& iniPath, const Config& config);
void ThrowLastError(const char* operation, DWORD error = GetLastError());

} // namespace mcd
