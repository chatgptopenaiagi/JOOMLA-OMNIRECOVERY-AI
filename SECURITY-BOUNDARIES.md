# Security and owner control

Scanning authorizes neither a database connection nor a credential change. Database inspection uses only the selected installation and authorized connection. Recovery requires a selected account, supported version, a database target matching the installation's resolved configuration, reviewed reason for fallback, exact confirmation, and an unexpired in-process preview record. Credential-only overrides are permitted; a different database cannot borrow the selected installation's version. The backend does not trust a caller-created preview or SQL plan. There is no password cracking, hash reversal, privilege bypass, cookie extraction or unrelated credential enumeration.

## Boundaries

| Boundary | Enforcement |
|---|---|
| Filesystem | Owner-approved roots, explicit external-file approvals, traversal budgets, skipped reparse points, metadata-oriented discovery |
| Configuration | Static parsing only; unresolved dynamic code stays unresolved |
| Database | Local-only default, validated identifiers, parameterized values, selected database/prefix/schema checks |
| SQL editor | Restricted SELECT grammar and revalidation at execution; no secret columns or write statements |
| Recovery | Joomla 4/5 gate; modern bcrypt; one account; snapshot/expiry checks; InnoDB and trigger visibility; transaction and verification |
| Credentials | Masked fields, optional current-user Windows Credential Manager, no plaintext settings/report storage |
| Evidence | Allowlisted metadata, redaction, current-user/SYSTEM directory ACL, deliberate export |
| Cloud | Disabled by default, HTTPS, exact-body opt-in, no local tool interface |
| Server state | Inspection only; no automatic ports/service/configuration repairs |

Windows administrators and processes running as the same user remain inside the local operating-system trust boundary. This application is not a sandbox against a compromised workstation. Managed runtime strings may remain in memory until collected; no promise of complete memory erasure is made. Screenshots, copied SQL and exported user metadata must be handled according to the owner's privacy needs. Exports prevent common CSV formula injection but are intentionally user-selected disclosures.

Password hashes are kept in memory only when needed for recovery concurrency checks and verification; old hashes are not routinely logged/exported. A password is never a process argument, URL, temporary file or cloud field. New password policy is at least 12 characters, no control/null characters, valid Unicode and at most 72 UTF-8 bytes to avoid bcrypt truncation. Generated values use 144 bits of cryptographic randomness. The normal password mechanism is bcrypt, never MD5.

Supported Joomla mechanisms remain preferable because direct database recovery does not run Joomla plugins/events or comprehensive authentication policy. Fallback preserves blocked status, MFA, sessions and other fields. A committed database reset is not a successful browser-login claim. Evidence identifies this distinction.

Unexpected errors should be reported without credentials. Do not include private configuration files, API keys, full database exports or real password hashes in issues. The release is unsigned and has not undergone an independent penetration test. Limitations are explicit in [Testing](TESTING.md).
