# Release notes — 1.0.0

Initial independent Windows x64 desktop release, developed and verified on 11 November 2026. Native WPF interface with nine work areas, dark/light themes, local evidence, static loader-aware discovery, database/account inspection, restricted SQL, and an explicitly confirmed transactional password recovery fallback.

The self-contained build uses .NET 10. It does not require Codex, a Python environment or cloud AI. No service, updater or automatic server repair is included. The app is unsigned.

Recovery is gated to Joomla 4/5; schemas, ACLs and concurrency are checked. PHP 8.2 verifies the generated bcrypt hashes. This does not establish every plugin, Joomla version, authentication extension or deployment as compatible. SQLite recovery exists only for isolated training fixtures. Supported application-level Joomla recovery is described rather than automatically executed. Arbitrary PHP configuration evaluation is intentionally unavailable.

Optional cloud assistance uses a configurable HTTPS chat-completions adapter. Mocked protocol tests pass; no real provider key or live cloud response was used in validation. See [TESTING.md](TESTING.md) and `artifacts/VERIFICATION-RESULTS.json` for evidence and remaining gaps.
