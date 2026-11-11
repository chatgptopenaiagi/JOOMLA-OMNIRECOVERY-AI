# Installation

Use Windows 11 x64. Unzip the release into a folder owned by your current user and run `JOOMLA-OMNIRECOVERY-AI.exe`. The application requests **asInvoker**, not elevation. Normal discovery and account inspection operate with your existing permissions. A self-contained release includes the .NET runtime; Codex and Python are not required. Windows may warn about an unsigned downloaded executable. This release is not code-signed.

Keep the release documentation with the executable. `Launch.cmd` opens normal mode and `Launch-Demo.cmd` opens isolated training mode. The demonstration creates synthetic data in your local application-data directory; it does not provide a running Joomla website.

## Build from source

Installations are not performed automatically by the launcher. With PowerShell 7 and .NET SDK 10.0.404 or a later 10.0.4xx patch, run `./Build.ps1`. The first restore downloads the three declared libraries and their dependencies into this project's `.packages` directory. Publish may restore the Windows x64 runtime pack. Build inputs are in `global.json`, `Directory.Build.props`, `NuGet.Config` and the project files. `./Start-Development.ps1 -Demo` starts the development build.

No Windows service is installed. No Apache configuration, firewall rule, global PATH, Joomla file or production database is changed by installation. A PHP executable is useful for local diagnostics but not required for bcrypt generation. Existing MySQL/MariaDB permissions are required to inspect accounts; the software does not supply or guess a root password.

## Data and removal

Use Evidence → Delete history for investigation records. Disconnect AI and remove saved connection credentials in Settings/connection controls before removing the application if desired. Removing the executable does not automatically erase investigation history or saved credentials. Per-user state is in `%LOCALAPPDATA%/JoomlaOmniRecoveryAI`; Credential Manager targets begin `JoomlaOmniRecoveryAI/`. Delete only application-owned entries you intend to remove. No uninstaller or automatic update service is included.
