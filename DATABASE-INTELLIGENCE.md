# Database intelligence

The database adapter inspects only the database selected by the resolved Joomla configuration. A successful inspection establishes access and the inspected schema; it does not prove that Joomla authentication or effective authorization works.

## Supported boundaries

| Adapter | Inspection | Recovery |
|---|---|---|
| MySQL / MariaDB | Selected database, bounded schema/account/ACL queries | Explicit Joomla 4.x/5.x fallback on eligible InnoDB users tables |
| SQLite | Explicit existing absolute local file; generic table inventory and Joomla-shaped fixture inspection | Disabled normally; enabled only through the explicit synthetic-fixture constructor |

SQLite is not represented as a supported production Joomla backend. No SQLite file is created by the repository. Database names and interpolated table identifiers use a conservative ASCII identifier allowlist; names outside that subset require supported Joomla administration instead of guessed quoting.

Host validation accepts an exact localhost name or loopback IP by default. Remote hosts require explicit opt-in. Remote MySQL connections require full TLS certificate verification. The connector uses a structured connection-string builder, disables local-file loading and user variables, disables pooling, sets a five-second connection timeout and ten-second command timeout. Local TLS is preferred where available. The affected-row setting reports changed rows for recovery verification. These options follow the [MySqlConnector connection reference](https://mysqlconnector.net/connection-options/).

## Prefix and schema identity

Account inspection requires the exact configured prefix and these tables:

- `users`: id, username, name, email, password, block, requireReset, lastvisitDate; a single-column id primary key.
- `user_usergroup_map`: user_id, group_id.
- `usergroups`: id, parent_id, title, lft, rgt.
- `assets`: id, parent_id, name, rules.

Required identifiers must refer to base tables. If the prefix is wrong or schema incomplete, the adapter returns no account selection. It may list other schema-validated prefix candidates for explicit configuration review. It never silently switches prefix or database, and candidates never become recovery targets automatically.

Inspection accepts an explicitly selected manual target. Recovery additionally requires a resolved installation configuration bound to the same engine, host, port, database and prefix; only credentials may differ. A version read from one installation does not authorize changes to another database. The SQLite fixture path is bound as well.

Schema inventory has a 2,000-table and 20,000-column MySQL budget. Account display is capped at 200 accounts; membership inspection at 10,000 rows, groups at 1,000, and asset hierarchy at 2,000. Truncation or exceeded budgets remain visible. SQLite inspection queries column metadata only for identifier-safe Joomla-shaped table names; other table names remain generic inventory entries.

## Authorization evidence

The inspector follows usergroup parents, detects cycles/missing parents and checks asset parent chains against one `root.1` asset. Root rules are parsed with bounded JSON depth/size. A `core.admin` or `core.login.admin` grant for an assigned/inherited group is described as a detected grant. It is never presented as a completed Joomla authorization evaluation.

Both Joomla's integer `1` and JSON boolean `true` are recognized as grant evidence; integer `0` and `false` are deny evidence. Other numbers, strings/null and duplicate definitions remain unknown. Conflicting inherited grant/deny evidence is explicitly uncertain. Membership truncation prevents authoritative privilege labels.

Group number 8 or the group title alone does not establish administrator authority. Component/action precedence, deny rules, extensions, account blocks and authentication providers can affect actual access. A broken or incomplete inheritance chain is reported as unknown. The UI must preserve those qualifiers.

Password hashes are excluded from account models and workbench projections. Old hashes are read privately only for an authorized recovery preview and optimistic concurrency check; they are not included in inspection results, previews or evidence reports.

## Verification

On 2026-11-11, the combined fixture suite passed 55/55 tests. See [integration results](artifacts/mariadb-integration-agent-tests.json). Its database coverage includes synthetic SQLite, two uniquely named databases on a separately initialized loopback MariaDB server under this workspace's `.local` directory, prefix/schema checks, inheritance, parameterized SELECT, recovery, stale identity, trigger refusal and connection failure. The tests did not modify a production database.

The optional integration suite requires `--mariadb-port=<port>`, refuses port 3306, verifies server port and workspace-contained data-directory identity, and rejects unexpected nonfixture databases before creating anything. Server initialization/start/stop is owned by the test operator, never by these adapters.

PHP interoperability is separately opt-in with `--php-path=<absolute-local-php-executable>`. Normal test runs require neither XAMPP/PHP nor a MariaDB server. Selecting an executable is an explicit local execution choice; the test invokes only fixed PHP code and passes synthetic data through standard input.

The optional MariaDB suite also contains a continuous discovery → external static configuration loader → resolved connection → account inspection → confirmed recovery test, using fresh synthetic file markers and database schemas. Its Joomla version marker is 5.4.8; no Joomla web runtime is installed or executed. This added test and the latest target-binding regressions are newer than the historical 55-test report above and require the final operator-run integration report for verification.

See [SQL restrictions](SQL-ENGINE.md) and [recovery protocol](ACCOUNT-RECOVERY.md).
