# Joomla discovery and static configuration

The scanner and static resolver find local Joomla source trees, read a deliberately restricted configuration grammar and catalog declared Apache mappings. They do not execute Joomla/PHP source, authenticate to databases, request websites or start/stop services. The separate `SiteReachability.CheckAsync` adapter performs an explicitly selected loopback-only unauthenticated HEAD request with an eight-second timeout and no redirects; it never runs as part of a scan. `Configured` means that settings were resolved, not that a site or database works.

Implementation is in `src/OmniRecovery.Infrastructure/Discovery`, namespace `OmniRecovery.Infrastructure.Discovery`:

| Entry point | Responsibility |
|---|---|
| `JoomlaDiscovery.ScanAsync(ScanOptions, progress, cancellation)` | Bounded local directory discovery and Joomla marker/version observations |
| `StaticConfigurationResolver.Resolve(path, approvedRoots, explicitlyApprovedFiles)` | Static connection resolution with external-loader approval boundaries |
| `ApacheConfigurationParser.Parse(path, approvedRoots, cancellation)` | Bounded Apache includes, listeners, document roots, virtual hosts and aliases |
| `ApacheConfigurationParser.LocalUrl(site, relativePath)` | Credential-free loopback HTTP/HTTPS URL construction |
| `WindowsSystemDiscovery.InspectAsync(roots, cancellation)` | Windows identity, relevant service metadata, TCP listeners and explicit version probes |

## Scope and bounded discovery

The caller selects roots. UNC/network roots and paths crossing filesystem reparse points are rejected. A broad volume root does not authorize traversal of `Users`; a personal profile or personal directory must be selected explicitly. Dependency/cache directories in `ScanOptions.ExcludedDirectories` are skipped. Excluded directories are intentional scope exclusions, not errors. No other drives or personal directories are added automatically.

The defaults are depth 7, 25,000 file entries, 6,000 visited/queued directories and 45 seconds. The implementation clamps depth to 20, files to 200,000, directories to 50,000 and seconds to 300, and considers at most 64 selected roots. Directory queue size is bounded as well as visitation. Depth exhaustion, access failures, cancellation and limits retain partial observations with findings rather than claiming complete coverage. Progress contains counts and the current selected path.

These are cooperative deadlines: synchronous filesystem/registry calls must return before cancellation or elapsed-time checks can run. They are not an operating-system guarantee that an unresponsive local device returns within a deadline. Marker probes inspect a small fixed set of paths per visited directory; `FilesVisited` counts enumerated file entries, not every metadata probe or source byte. Filesystem contents may change during inspection; this is not a snapshot or an adversarial filesystem isolation mechanism.

## Joomla evidence and versions

A file called `configuration.php` is insufficient. Detection requires `includes/defines.php`, `includes/framework.php`, an administrator directory, and either the core Joomla manifest or a supported version file. Candidate source files are never executed.

Version sources are:

- `administrator/manifests/files/joomla.xml`, with a Joomla-identifying name and numeric version. XML DTDs and external entities are prohibited.
- `libraries/src/Version.php`, using literal major/minor/patch assignments.
- Legacy `libraries/cms/version/version.php` or `libraries/joomla/version.php`, using literal release/development-level assignments.

Each version file is limited to 128 KiB. An unresolved or invalid version stays `UNKNOWN`. Missing configuration does not erase a valid marker observation, but produces an incomplete-installation finding. A marker finding is not proof that all files, extensions, data or deployment assets are intact.

## Static PHP resolution

The resolver reads at most 16 files, a loader depth of 8, 256 KiB per file and 2 MiB total, with a three-second cooperative inspection budget. It requires exactly one resolvable `JConfig` declaration. Supported data assignments include case-sensitive public/`var` properties, literal strings, unambiguous decimal integers, string concatenation, parentheses, `__DIR__`, `__FILE__`, `dirname(...)`, and explicitly named literal `getenv('NAME')` calls for property values. The environment is never enumerated. Missing environment values remain unresolved.

Comments are ignored lexically, and quoted comment-like text remains text. Interpolated strings, constructors/methods, conditional execution, duplicate declarations, dynamic credential expressions, unsupported string escapes and ambiguous leading-zero integers are not evaluated. Unknown source statements prevent a best-guess connection. The recognized conventional `_JEXEC` direct-access guard is allowed. This is a restricted parser, not a PHP compatibility implementation; legitimate complex configurations can require manual settings or an explicitly selected simpler configuration.

Anchored `require`, `require_once`, `include` and `include_once` chains can use `__DIR__` or `dirname(__FILE__)` concatenated with literal paths. CWD/include-path-dependent relative loaders remain unsupported. A loader outside approved roots is listed in `PendingApprovalPaths` without being read. Selecting an exact approved file authorizes that file only; it does not approve its parent directory or further external loaders. Cycles, oversized files and reparse paths fail closed.

Required fields are `dbtype`, `host`, `user`, `password`, `db` and `dbprefix`. Empty passwords remain representable; missing/dynamic passwords do not. `mysqli` and `pdomysql` normalize to `mysql`. Explicit ports and host-suffixed ports are validated, including bracketed IPv6; conflicting ports remain unresolved. Prefixes use a bounded ASCII letter/digit/underscore identifier. Remote access is never enabled by configuration resolution. Other database-engine names can be observed; repository support and authorization are separate checks.

Connection settings, including the password, exist only in the in-memory `ConfigurationResolution.Connection`, which is excluded from JSON. Findings describe resolution outcomes without echoing PHP source or credential values. `LiveSite` is exposed only if it is a credential-free loopback HTTP/HTTPS URL. No database login occurs here.

## Apache catalog and local URLs

The parser supports quoted directives, comments, static `Define` expansion, `ServerRoot`, `Listen`, `ServerName`, `DocumentRoot`, `SSLEngine`, `Alias`, `VirtualHost`, `Include` and `IncludeOptional`. Filename-only include globs are bounded and confined to approved roots. It considers at most 64 files, depth 8, 256 KiB per file, 2 MiB total, 5,000 lines per file and four seconds cooperatively. Unknown variables and out-of-scope includes are reported and skipped. Cycles are reported.

The result is a catalog of declared mappings, not Apache's effective runtime configuration. Module availability, conditional activation, rewrite rules, authorization policy, proxying, DNS/hosts mappings and actual virtual-host selection are not evaluated. Repeated include files are deduplicated for bounded inspection. No explicit port means no invented default port. Aliases and document roots outside the scan scope may be described, but their target contents are not traversed.

Loopback URLs can be derived for discovered Joomla roots under a declared document root or alias. They remain untested mappings. Remote hosts and credential-bearing URLs are not returned as navigation targets. phpMyAdmin aliases produce configured local URL findings only; the parser does not request phpMyAdmin.

## Windows diagnostic behavior

Service inspection reads relevant local registry entries and queries service status through read-only Service Control Manager handles. It strips arguments from recorded executable paths and never records service command-line arguments. TCP listener metadata records distinct ports, not authenticated service identities.

Known PHP/Apache executable paths beneath selected roots are checked directly; there is no recursive executable search. At most eight candidate tools are invoked. PHP uses `-n -v`, disabling PHP INI loading. Apache uses `-v`. Each tool gets a four-second timeout and bounded stdout/stderr capture. Only a recognized version token is published, not arbitrary tool output. The version/Apache phase also has an 18-second cancellation budget. A timed-out diagnostic child can be terminated; existing servers/services are never terminated. Initial synchronous metadata collection remains subject to the cooperative-IO limitation above.

PHP's reported version does not prove that Joomla-required extensions are configured: `-n` intentionally skips the INI. Apache version does not prove a particular configuration is active. Services and listening ports are observations, not a guarantee that a selected Joomla application is reachable.

## Verification checkpoint

On 2026-11-11, the Infrastructure and Tests projects built with zero errors. The shared synthetic suite passed **48/48**, including **22 discovery/configuration/Apache tests**. The remaining compiler warning at that checkpoint was in the separate AI module.

Tests cover marker versus filename detection, modern version constants, XML entity blocking, partial scan coverage, cancellation/progress, directory exclusions and queue bounds, UNC rejection, a temporary filesystem symlink, comment handling, secret-safe serialization, explicit environment lookup, chained loaders and exact-file approval, duplicate/dynamic/conditional PHP, case sensitivity, cycles and byte limits, IPv6/port conflicts, Apache includes/aliases/virtual hosts, unknown variables and safe URLs. Fixtures are created only below the workspace `.local/tests` and remove only their own directories.

The test report is `.local/tests/discovery-validation-edge-results.json`. No installed Joomla source, live database, actual configuration credentials or workstation-wide scan was used by that synthetic test run. Production readiness, all PHP syntax variants, host service diagnostics and live URLs require separate explicit verification.

## Explicit real lab observation

After the synthetic checkpoint, a separately authorized read-only observation of the selected public Joomla lab ran using these actual discovery/resolver classes and `MySqlAccountRepository.InspectAsync`. The latest observation is **2026-11-11 10:57:20 UTC**, after correcting the database inspector's interpretation of numeric Joomla ACL grants.

| Observation | Result |
|---|---|
| Joomla version | 5.4.8 |
| Static configuration | Configured; two-file reference chain resolved |
| Database metadata/account inspection | Verified; MariaDB 10.4.32 |
| Schema tables | 76 |
| Accounts observed | 1 |
| Accounts with administrator-grant evidence | 1; inspected asset parent chains reach the root, but action-specific authorization and Joomla login remain unverified |
| Declared Apache ports | 443 and 8080 |
| Site/Apache reachability | Not tested |
| Recovery previews or database writes | None |

The ACL shape diagnosis found 11 root action objects and 16 numeric rule values, all equal to 1. Both `core.admin` and `core.login.admin` contain a numeric grant value. The earlier zero-grant result was an inspector compatibility defect (boolean-only recognition), not a database change. The database agent added numeric-grant regression coverage before this repeat inspection.

Only nonsecret summaries, ACL value-kind/count statistics, finding codes and private source-reference metadata were retained in `.local/real-discovery-validation/observations.json` and `observations-acl-diagnosis.json`. No raw ACL documents, credentials, usernames, email addresses, group IDs or account identifiers were persisted in that evidence. This observation does not establish Joomla login or recovery behavior.

Architecture diagrams: [discovery-diagrams.md](docs/discovery-diagrams.md).
