#include "../common/common.h"

#include <filesystem>
#include <iostream>

int wmain() {
    try {
        for (unsigned attempts = 1; attempts < 30; ++attempts) {
            const unsigned delay = mcd::BackoffSeconds(attempts, 60, 21600, L"PC-001");
            if (delay < 60 || delay > 21600) throw mcd::Error("Backoff left configured bounds.");
        }
        const auto testRoot = std::filesystem::temp_directory_path() / L"GLPIAgentDeployerNativeTest";
        std::filesystem::create_directories(testRoot);
        const auto ini = testRoot / L"config.ini";
        mcd::Config original;
        original.domainController = L"dc01.contoso.test";
        original.searchBases = {L"OU=Workstations,DC=contoso,DC=test", L"OU=Laptops,DC=contoso,DC=test"};
        original.agentMsiPath = testRoot / L"GLPI-Agent.msi";
        original.remoteRunnerPath = testRoot / L"runner.exe";
        original.databasePath = testRoot / L"state.db";
        original.logPath = testRoot / L"deployer.log";
        original.httpSecretPath = testRoot / L"secret.bin";
        original.serverUrl = L"https://glpi.contoso.test/";
        original.httpUser = L"inventory-user";
        original.tag = L"workstations";
        original.workerCount = 7;
        mcd::WriteConfig(ini, original);
        const auto loaded = mcd::LoadConfig(ini);
        if (loaded.domainController != original.domainController || loaded.searchBases != original.searchBases ||
            loaded.agentMsiPath != original.agentMsiPath || loaded.logPath != original.logPath ||
            loaded.httpSecretPath != original.httpSecretPath || loaded.serverUrl != original.serverUrl ||
            loaded.httpUser != original.httpUser || loaded.tag != original.tag || loaded.workerCount != 7)
            throw mcd::Error("Configuration round-trip failed.");
        std::filesystem::remove_all(testRoot);
        std::wcout << L"All native tests passed.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Test failure: " << error.what() << "\n";
        return 1;
    }
}
