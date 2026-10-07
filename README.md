# GLPI Agent Deployer

A small native C++ Windows service that discovers Windows computers in Active Directory and installs or upgrades the official GLPI Agent. It has no web UI and cannot deploy arbitrary software.

## How it works

1. Searches the configured Active Directory domain or OU subtrees for enabled Windows computer accounts.
2. Checks due computers over SMB and the Windows Service Control Manager (SCM) RPC interface.
3. Reads the installed GLPI Agent version when the `glpi-agent` service exists.
4. Does nothing when the installed version matches or is newer than the configured MSI.
5. For a missing or older agent, copies the MSI and a restricted native helper to a unique directory through `ADMIN$` and verifies both copies with SHA-256.
6. Runs the helper as a temporary LocalSystem service. The helper stops an existing agent when necessary and launches the GLPI MSI silently with the configured server, authentication, tag, and inventory settings.
7. Verifies the resulting service and version, then removes the temporary service and staged files.
8. Retries offline or failed computers with capped exponential backoff.

AD discovery defaults to every 15 minutes. Compliant agents are rechecked every 24 hours. Replacing the configured MSI with a newer version makes all discovered computers due for a version check; newer agents are never downgraded.

## Requirements

- An x64 Windows 10/11 target environment and a domain-joined Windows Server 2022 or Windows 10/11 deployer host.
- A dedicated `DOMAIN\user` with read access to the selected AD computer objects and local Administrator rights on every target. Do not use a Domain Admin account.
- TCP 445 for `ADMIN$`, TCP 135, and the configured dynamic RPC range from the deployer to targets.
- An official x64 GLPI Agent MSI.

## Install

Build the project, then run `artifacts\GLPI-Agent-Deployer.exe` as Administrator. The terminal installer asks for:

- the service account and password;
- the GLPI Agent MSI;
- the GLPI server URL and optional tag;
- optional GLPI HTTP username and password;
- the whole domain or one or more OU distinguished names;
- discovery/concurrency settings and optional plaintext logging.

The MSI is copied into the installation directory; it does not need to remain on a share. The service-account password is stored only by Windows SCM. An HTTP password is protected locally with machine DPAPI and restricted ACLs. Credentials are not written to SQLite or the plaintext log.

State is stored in `C:\ProgramData\GLPI Agent Deployer\state.db`. Optional plaintext logging defaults to `C:\ProgramData\GLPI Agent Deployer\deployer.log`, rotates at 5 MiB, and keeps one backup.

## Build

Install Visual Studio 2022 with **Desktop development with C++** and a current Windows SDK, then run:

```bat
scripts\build-native.cmd
```

The script builds the statically linked service, restricted remote helper, terminal installer, and native tests. The finished installer is `artifacts\GLPI-Agent-Deployer.exe`. No .NET runtime or third-party deployment tool is required.

## License

MIT. See [LICENSE](LICENSE).
