# Final engineering status — 1.0.0

Delivered a self-contained Windows x64 WPF application, modular C# backend, tests, documentation, reproducible build scripts, launchers and a public-source publication package. Open `release/JOOMLA-OMNIRECOVERY-AI.exe` or use `Launch.cmd`.

## Independently verified

| Area | Result | Boundary |
|---|---|---|
| Release build | Passed, zero warnings/errors | Existing .NET 10 SDK; self-contained win-x64 |
| Automated suite | 61/61 combined checks passed | 53 normal synthetic checks + PHP + seven disposable MariaDB checks |
| Packaged GUI | Exited 0 in smoke validation | Nine pages, themes, SQL/export and synthetic recovery |
| Normal GUI interaction | Verified through Windows UI | Startup, scope controls, navigation and offline guidance; no scan/connect/reset automatically |
| External configuration loader | Verified | Synthetic fixtures and selected real two-file configuration |
| Live account discovery | Read-only verified | Joomla 5.4.8 / MariaDB 10.4.32; one account with administrator-grant evidence |
| Password recovery | Verified in disposable databases | Exact one-row update, preserved other account/database, PHP bcrypt verification |
| Credential storage | Synthetic round trip passed | Unique app-owned Windows Credential Manager target, removed afterward |
| Optional AI | Mocked protocol tests passed | No live key/provider request; local operation independent |
| Production recovery/login | Not tested | No existing Joomla account or production database was changed |

The combined count includes the normal suite; repeated build and integration runs are not additional unique tests. Full results: [verification](artifacts/VERIFICATION-RESULTS.json), [normal checks](artifacts/automated-tests.json), [isolated checks](artifacts/isolated-integration-tests.json), [GUI checks](artifacts/gui-verification.json).

## Implemented workflow

Scope selection → Joomla detection → static configuration references → selected database/schema → account metadata and ACL evidence → supported-recovery guidance → explicit database fallback reason → generated/entered password → expiring preview → owner confirmation → transactional single-account verification → browser navigation to the configured administrator URL.

Owner-selected overrides can inspect another target, but recovery cannot borrow the version of a different installation. Cloud responses cannot trigger SQL or recovery. Existing Apache ports 8080/443 were observed and preserved. Test servers were isolated and stopped using owned-process identity checks.

## Remaining limitations

The direct fallback accepts Joomla 4.x/5.x with a matching resolved configuration and eligible schema. Unknown/3.x/6.x releases are refused. A complete Joomla browser login after reset, every authentication plugin, MFA/session behavior and complete effective ACL evaluation remain unverified. Dynamic PHP evaluation, arbitrary SQL, automatic server repairs, database backups, a signed installer and automatic updates are outside this release. See [testing](TESTING.md) for all material boundaries.

The application is a tested first release with explicit compatibility limits. It is not represented as universally compatible or independently security-certified. [Architecture](ARCHITECTURE.md), [user guide](USER-GUIDE.md), [recovery](ACCOUNT-RECOVERY.md) and [security boundaries](SECURITY-BOUNDARIES.md) explain operation and ownership controls.
