# Account recovery

The recovery service implements a narrow, explicitly opted-in database fallback. Joomla-supported recovery and an authorized administrator should be considered first. Inspection, a detected privilege grant or an AI recommendation never authorizes a password change.

## Preconditions and preview

`RecoveryService.PreviewAsync` requires explicit fallback opt-in, a 12–500 character reason, an exact installation/account and a recognized Joomla 4.x or 5.x release version. Unknown versions and other major versions are refused. The UI records the reason only through its sanitized evidence policy; this service does not copy it into SQL or account state.

The selected target must match the selected installation's resolved configuration: engine (with mysql/mysqli/mariadb treated as aliases), host, port, database and prefix. SQLite fixtures also bind their exact local file. Credentials may be overridden for an authorized operator; changing the target makes it inspection-only until the matching installation is resolved. A manually entered or unresolved target cannot borrow another installation's version to authorize fallback. Version evidence comes from inspected installation files and can still be stale; this binding does not prove the database's migration state or a live Joomla login.

The repository validates the exact selected schema/prefix and reads the target account privately. MySQL direct fallback requires an InnoDB users table, a unique primary-key account identity, no users-table triggers, and sufficient direct `TRIGGER` or `ALL PRIVILEGES` grant evidence to trust trigger metadata visibility. Role-only or otherwise ambiguous visibility fails closed. An empty `information_schema.TRIGGERS` result alone is insufficient.

A preview contains the installation/version, database/prefix, account id/username, method, parameterized SQL outline, expiry and warnings. A cryptographic nonce binds it to an immutable private account snapshot and connection fingerprint, including database, prefix, host/port, credential identity and SQLite path where relevant. The old hash is never returned. The same repository and recovery-service instances must be retained through confirmation.

Previews expire after five minutes. The user must enter the exact `RESET <username>` confirmation and explicitly retain fallback opt-in. Changed previews, another connection, expired/unissued tokens and replay are refused. A mutation attempt consumes the token; a new attempt requires a new preview.

## Password handling

Generated passwords contain 24 ASCII characters from 18 cryptographically random bytes. Manually supplied passwords must contain at least 12 characters, no null/control characters or malformed Unicode, and at most 72 UTF-8 bytes. The byte limit is rejected explicitly rather than silently truncated. [PHP's bcrypt documentation](https://www.php.net/manual/en/function.password-hash.php) defines the underlying limit.

`BCryptPasswordHasher` emits cost-12 `$2y$` hashes. Joomla's [5.4 UserHelper source](https://raw.githubusercontent.com/joomla/joomla-cms/5.4-dev/libraries/src/User/UserHelper.php) identifies that bcrypt revision. A synthetic Unicode password/hash produced by this implementation was verified by the installed PHP `password_verify` through standard input. Passwords and hashes were absent from command arguments, files and test output. This verifies that hashing boundary, not a complete Joomla login.

The PHP interoperability test is optional and requires `--php-path=<absolute-local-php-executable>`; it does not assume a `C:\xampp` installation. Disposable MariaDB integration independently requires `--mariadb-port=<nondefault-port>`. Normal build/test execution does not require either external runtime.

Passwords and private preview snapshots remain process-memory data. Managed strings are not a secure-erasure guarantee. The application must not log, persist, export or send them to an AI provider; closing the password input and application ends their ordinary lifetime. The only intended persistent password-derived value is the committed account hash.

## Transaction

1. Revalidate the connection, prefix, version, nonce and hash format.
2. Reopen the selected database and validate schema/engine/trigger eligibility.
3. Begin a serializable transaction and lock the exact user with `SELECT ... FOR UPDATE` on MySQL/MariaDB.
4. Recheck current InnoDB engine and trigger visibility while the selected table's metadata lock is held.
5. Require the id, exact username, old hash, block and requireReset values to match the private preview snapshot.
6. Execute a parameterized update of **password only**, with id, username and previous hash predicates; require exactly one changed row.
7. Read the same account inside the transaction and verify the new hash and unchanged id/username/block/requireReset.
8. Commit only after those checks. Before-commit failures are rolled back; unconfirmed rollback is reported distinctly.

If commit acknowledgement is interrupted, the outcome is `COMMIT_OUTCOME_UNKNOWN`. The application must not automatically retry: the server may have committed. Inspect the account through Joomla before deciding what to do next.

The operation does not unblock accounts, disable MFA, change groups, clear sessions, reset requireReset, run plugins or invoke Joomla lifecycle hooks. A database update is not proof of successful login. Existing reset requirements remain in force; review sessions and change the temporary password through Joomla after authorized access is restored.

## Verified scope

Synthetic SQLite tests verify confirmation, version/opt-in gates, nonce expiry/replay, connection/file/prefix identity, stale account/hash, cancellation, exact-row changes, preserved controls and rollback following an injected verification failure. SQLite writes require the explicit synthetic constructor and are not production support.

The isolated MariaDB fixture verifies the real connector/transaction path, a nondefault prefix, inherited ACL evidence, unchanged second database/account/MFA/session markers, stale-hash refusal and trigger refusal. The final combined run passed **61/61** checks on 2026-11-11: [results](artifacts/isolated-integration-tests.json). Production recovery and complete Joomla login acceptance remain unperformed.

The passing opt-in MariaDB suite includes one continuous application path: bounded Joomla discovery, a public static PHP loader pointing to a private configuration, configuration resolution, selected-database inspection, bound preview, exact confirmation and one-password reset. It creates fresh synthetic Joomla markers/version 5.4.8 and two isolated synthetic schemas; it checks the other account and database remain unchanged. This is not a full web Joomla installation or login test.
