# Testing and verification

Validation uses synthetic fixtures and explicitly selected read-only live observations. Test presence does not establish compatibility with every Joomla installation. Machine-readable results are in `artifacts/VERIFICATION-RESULTS.json`; individual checks are in the referenced reports.

The final combined run on 2026-11-11 passed **61/61 checks**: 53 normal synthetic checks, one PHP interoperability check and seven isolated MariaDB checks. A separate actual-WPF smoke run verifies rendered navigation and the synthetic GUI recovery path. These counts are overlapping suites, not additive unique tests across repeated runs.

An earlier disposable-server attempt failed before SQL because the native MariaDB process exited and produced a crash dump. Its private evidence was preserved. The harness now verifies protocol-level readiness and uses an available port below the Windows dynamic range. The subsequent fresh fixture passed all checks. The precise native-crash cause was not established; no repair of the installed server was attempted.

## Reproduce

`./Build.ps1` restores, builds, runs the normal synthetic suite and publishes the Windows release. Tests run as a simple .NET console harness with nonzero exit on failure; no testing-framework installation is required. Outputs go to `.local/tests` and `artifacts`. Each test has a 90-second maximum wait. The release GUI accepts `--demo` for training and `--smoke-test` for synthetic validation and screenshots; smoke mode exits automatically and never connects to a production database.

`./Test-IsolatedMariaDb.ps1` is an **opt-in** integration test using existing MariaDB tools and PHP. It creates a unique data directory under `.local`, initializes a fresh server with a known empty synthetic root account, selects an unused loopback port, runs guarded fixture tests, and terminates only its owned server process. It does not guess credentials or connect to the usual production port. The C# preflight requires an explicit nondefault port, a datadir under this workspace's `.local`, and absence of unexpected non-fixture schemas. No Windows service is installed. Private disposable data is preserved for diagnosis and excluded from publication.

PHP interoperability can also run with `--php-path=<absolute existing php.exe>`; it sends a synthetic password and hash through redirected standard input. Neither value is written to arguments, temporary files or output. Normal builds do not require PHP. MariaDB tests require `--mariadb-port=<explicit disposable port>` and are excluded by default.

## Covered behavior

- Multiple Joomla markers/version metadata, static external loaders, scope approval, unsupported dynamic code, environment-variable references, limits, cancellation, duplicate roots and inaccessible/missing paths.
- Apache include/virtual-host/alias parsing, nonstandard ports and local URL handling.
- Selected database/prefix schema validation, parameterized SQL, identifier rejection, forged-plan rejection, local/remote gates and nonsecret account results.
- Group/asset ancestry, Boolean and numeric Joomla ACL grants, incomplete inheritance and uncertain effective privileges.
- Password strength/UTF-8 limits, PHP bcrypt compatibility, one-use/expired/tampered previews, selected account identity, optimistic concurrency, trigger refusal, transaction verification, rollback and preservation of unrelated data.
- Windows Credential Manager using a unique synthetic entry, JSON secret exclusion, evidence allowlists/history deletion, CSV formula protection.
- Disabled cloud mode, exact-body preview approval, tampering/replay rejection, response bounds/errors/cancellation and HTTPS policy using mocked HTTP.
- Loopback-only unauthenticated HEAD diagnostics with redirects disabled.
- Actual WPF navigation, demo account table, SQL execution, recovery preview/confirmation/result, dark/light rendering and minimum-window layout.

## Read-only live scope

The development workstation's selected Joomla 5.4.8 installation was statically detected through its two-file configuration chain; an authorized existing application connection inspected MariaDB 10.4.32. Apache configuration preserved HTTP 8080 and HTTPS 443. No real recovery preview, UPDATE, schema change, account reset, login submission or server repair was performed. Local paths and account identities remain in excluded private evidence, not the public source repository.

## Explicit gaps

- Joomla 4/5 version gates and schema compatibility are implemented; a full browser login after reset was not exercised against a real Joomla distribution. Tests use faithful selected schemas, not an installed synthetic CMS site. Joomla 3/6/unknown versions are refused for fallback.
- Authentication plugins, external SSO, MFA, complete ACL precedence, revoked sessions and every extension are not validated. A root grant is evidence, not a full authorization decision.
- There was no live cloud-provider call. Endpoint/model compatibility and provider billing require owner configuration and consent.
- No signed installer, code-signing certificate, auto-update system or independent security assessment is included.
- Filesystem deadlines are cooperative: a Windows kernel/network filesystem call can delay cancellation. Reparse points and remote filesystem scopes are rejected; no hard-kill scan subprocess is used.
- System discovery uses bounded known layouts rather than a full executable inventory. PHP extension activation, HTTP.sys URL reservations, excluded-port ownership and complete Apache runtime semantics are not reconstructed automatically. The local guide provides a repair investigation plan, not an automatic repair.
- The restricted SQL workbench deliberately excludes arbitrary SQL/functions/joins. UI account listing is capped at 200; validated queries can select a bounded subset. No full-database backup/restore is performed.
