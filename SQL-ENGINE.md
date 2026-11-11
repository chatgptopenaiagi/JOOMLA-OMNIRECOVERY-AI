# SQL workbench engine

The workbench accepts a deliberately small SELECT language. It is not a general-purpose SQL console and does not execute arbitrary SQL supplied by the UI or an AI model.

## Accepted grammar

```text
SELECT column [, column ...]
FROM exactConfiguredPrefix_table
[WHERE column comparison literal [AND column comparison literal ...]]
[ORDER BY column [ASC|DESC]]
[LIMIT integer]
```

Comparisons are `=`, `<>`, `<`, `>`, `<=` and `>=`. Literals are integers or single-quoted text with doubled quotes. Parsed values become provider parameters. Integers do not become identifiers. The emitted SQL quotes validated identifiers and never interpolates data values.

The selected database comes from the connection, not the statement. Only one exact-prefix table is accepted. There are at most 20 distinct projected columns, eight predicates, 128 tokens and 8,192 input characters. LIMIT defaults to 200 and must be 1–200. Identifiers may be bare or backtick-quoted, but both forms must satisfy the same conservative ASCII identifier validation. Backticks inside string literals remain literal data. The adapter emits canonical identifier quoting so generated SELECT text can be reviewed and parsed again.

| Table suffix | Allowed columns |
|---|---|
| users | id, username, name, email, block, requireReset, lastvisitDate, registerDate, sendEmail |
| user_usergroup_map | user_id, group_id |
| usergroups | id, parent_id, title, lft, rgt |
| assets | id, parent_id, name, title, rules, lft, rgt, level |

Actual column availability still depends on the selected schema; an allowlisted optional column does not establish that it exists. Generic SQLite inventory is separate from this Joomla-table workbench.

## Refused inputs

Wildcards, password/authentication columns, aliases, joins, functions, subqueries, UNION, OR, comments, semicolons, multiple statements, database qualification, variables, backslash escapes, output files, DDL and every data-changing statement are unsupported. This also rejects `INTO OUTFILE`, `LOAD_FILE`, `SLEEP` and equivalent attempts before the connector receives them.

`ExecuteReadOnlyAsync` does not trust a caller-supplied `ReadOnly` flag. It reconstructs and reparses the allowlisted plan, checks database and table metadata, revalidates the exact configured Joomla schema, and binds values as parameters. A manually forged `QueryPlan` cannot bypass that parser.

Example accepted input:

```sql
SELECT id, username, block FROM x9_users WHERE username='fixture_admin' ORDER BY id LIMIT 20
```

Here `x9_` must be the explicitly selected prefix. The generated command uses a parameter for the username. A string resembling SQL injection remains a literal value, as verified in both SQLite and the isolated MariaDB fixture.

## Mutation separation

There is no SQL-editor mutation mode. The recovery service uses its own fixed parameterized command and preview/confirmation/transaction protocol. Its SQL outline is explanatory, not an executable workbench script. See [account recovery](ACCOUNT-RECOVERY.md).

The parser, forged-plan rejection, exact prefix/database behavior and database-adapter execution were tested with synthetic fixtures. The final combined 2026-11-11 run passed 61/61 checks: [results](artifacts/isolated-integration-tests.json). Those results do not authorize other SQL or prove arbitrary database/provider compatibility.

External-runtime checks are optional: `--mariadb-port=<port>` enables the guarded disposable-server suite and `--php-path=<absolute-local-php-executable>` enables PHP bcrypt verification. Neither flag is required for the normal synthetic test suite.
