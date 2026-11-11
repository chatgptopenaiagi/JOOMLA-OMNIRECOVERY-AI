# Architecture

WPF provides a native, accessible Windows interface using the installed .NET 10 toolchain. A C# backend avoids packaging a second Python runtime. MySqlConnector provides parameterized database access; Microsoft.Data.Sqlite stores evidence and isolated test fixtures; BCrypt.Net-Next implements PHP-compatible bcrypt. These dependencies are project-local. Runtime operation has no dependency on Codex, PowerShell, XAMPP's control panel, or other engineering repositories.

```mermaid
flowchart LR
 Owner[Owner] --> GUI[WPF desktop]
 GUI --> Controller[Application controller]
 Controller --> Discover[Bounded discovery]
 Discover --> Resolve[Static PHP resolver]
 Controller --> DB[Database adapters]
 Controller --> Recovery[Preview / explicit confirmation / transaction]
 Recovery --> DB
 Controller --> Evidence[Nonsecret SQLite evidence]
 Controller --> Local[Offline guidance]
 Controller --> Preview[Sanitized disclosure preview]
 Preview -->|Separate owner approval| Cloud[Optional HTTPS provider]
 Controller --> Vault[Windows Credential Manager]
```

`OmniRecovery.Core` contains contracts, status records and stable identities. `Infrastructure/Discovery` has filesystem and system adapters. `Database` owns schema validation, SQL allowlisting, ACL interpretation and transaction boundaries. `Recovery` owns version/password policy and one-use confirmation. `Security`, `Evidence`, `Ai` and `Services` have independent contracts. `Desktop` owns navigation, display, selection and explicit user interactions. Tests exercise these boundaries without starting unknown application scripts.

```mermaid
flowchart TD
 Config[Public configuration.php] --> Parse[Tokenize static expressions]
 Parse -->|Literal approved reference| Private[External private configuration]
 Parse -->|Dynamic / ambiguous| Unknown[Unresolved: request authorized manual connection]
 Private --> Memory[In-memory connection settings]
 Memory --> Select[Selected database and prefix]
 Select --> Schema[Validate users / map / groups / assets]
 Schema --> Metadata[Account metadata and ACL evidence]
```

The resolver never evaluates configuration PHP. Unknown or conflicting constructs remain unresolved. Secret fields are excluded from JSON serialization; no private configuration source is copied into reports.

```mermaid
erDiagram
 USERS ||--o{ USER_USERGROUP_MAP : belongs
 USERGROUPS ||--o{ USER_USERGROUP_MAP : contains
 USERGROUPS ||--o{ USERGROUPS : ancestry
 ASSETS ||--o{ ASSETS : hierarchy
 ASSETS }o--o{ USERGROUPS : ACL_rules
```

```mermaid
flowchart LR
 Discover[Discover installation] --> Inspect[Inspect selected database]
 Inspect --> Select[Select account]
 Select --> Supported[Prefer supported Joomla recovery]
 Supported -->|Unavailable; explicit fallback reason| Preview[Identity + schema + expiring preview]
 Preview --> Confirm[Owner confirms exact target]
 Confirm --> Lock[Lock one row and compare prior state]
 Lock --> Update[Replace only password hash]
 Update --> Verify[Verify value and affected row count]
 Verify --> Commit[Commit / nonsecret audit]
 Lock -->|Failure| Rollback[Rollback and report]
 Update -->|Failure| Rollback
 Verify -->|Failure| Rollback
```

No service listens on behalf of this application. Cloud providers receive a deliberately small approved request and cannot invoke local tools. Account data and filesystem access remain local. Remote database connections require separate opt-in and verified TLS; ordinary connections are loopback-only.

```mermaid
flowchart LR
 Source[Core + Infrastructure + WPF] --> Build[.NET 10 SDK]
 Build --> Tests[Synthetic and optional isolated integration tests]
 Tests --> Publish[win-x64 self-contained single-file publish]
 Publish --> Exe[JOOMLA-OMNIRECOVERY-AI.exe]
 Exe --> State[Per-user protected local data]
```

Runtime data is under `%LOCALAPPDATA%/JoomlaOmniRecoveryAI/user`; demo data is under the separate `demo` directory. Evidence history and settings have current-user/SYSTEM ACLs. Credentials live in the current user's Windows Credential Manager. Managed strings cannot guarantee immediate physical zeroization; secrets are minimized and never intentionally logged. Native save buffers are cleared.
