using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using Microsoft.Win32;
using OmniRecovery.Core;

namespace OmniRecovery.Desktop;

public partial class MainWindow
{
    private void BuildPages()
    {
        BuildHome();
        BuildInstallations();
        BuildDatabase();
        BuildAccounts();
        BuildRecovery();
        BuildSql();
        BuildAssistant();
        BuildEvidence();
        BuildSettings();
    }
    private Border Metric(string label, out TextBlock number, string note)
    {
        number = Text("0", 34, false, FontWeights.SemiBold);
        number.Margin = new Thickness(0, 10, 0, 5);
        return Card(Stack(Text(label, 12, true, FontWeights.SemiBold), number, Text(note, 11, true)));
    }
    private void BuildHome()
    {
        var hero = Stack(
            Text("CONTROLLED RECOVERY, CLEAR EVIDENCE", 10, false, FontWeights.Bold),
            Text("Your Joomla estate.\nOne deliberate workflow.", 32, false, FontWeights.SemiBold),
            Text("Find installations, understand their configuration, inspect accounts,\nand recover access with a reviewable record of every action.", 14, true),
            Row(Action("Discover installations", ScanAsync, true, true), Action("Review scan scope", () => Navigate("Settings"))));
        ((TextBlock)hero.Children[1]).Margin = new Thickness(0, 12, 0, 14);
        var heroCard = Card(hero, 28);
        heroCard.BorderBrush = new SolidColorBrush(Color.FromRgb(94, 86, 171));
        var metrics = Columns(Metric("INSTALLATIONS", out _installationCount, "Within your selected scope"),
            Metric("CONFIGURED", out _configuredCount, "Resolved connection targets"),
            Metric("ACCOUNTS", out _accountCount, "From explicit DB inspection"),
            Metric("EVIDENCE", out _evidenceCount, "Recent local event records"));
        var workflow = Stack(Text("A recovery you can review", 18, false, FontWeights.SemiBold),
            Step("01", "Discover & resolve", "Select folders. Follow configuration references only within an approved scope."),
            Step("02", "Inspect the exact target", "Verify the database, table prefix and account identity using read-only queries."),
            Step("03", "Approve & verify", "Review the recovery method and target. A reset needs owner authorization and exact confirmation."));
        _homeContext = Text("No workstation inspection has run.\nUse the button below to inspect scoped local tools and services.", 13, true);
        _homeContext.Margin = new Thickness(0, 12, 0, 10);
        var machine = Stack(Text("Local environment", 18, false, FontWeights.SemiBold), _homeContext,
            Row(Action("Inspect local environment", InspectSystemAsync, false, true)));
        _toolGrid = Table("Observed local tools", 170, ("Tool", "Name", 1), ("Version", "Version", 1), ("Status", "Status", 1));
        machine.Children.Add(_toolGrid);
        _serviceGrid = Table("Observed Windows services", 170, ("Service", "DisplayName", 1.4), ("Status", "Status", 0.7), ("Executable", "Executable", 2.4));
        _siteGrid = Table("Observed Apache sites", 150, ("Host", "Host", 1), ("Port", "Port", 0.5), ("Document root", "DocumentRoot", 2), ("Configuration", "ConfigurationPath", 2));
        _listenerText = Text("Listening ports have not been inspected.", 12, true);
        var servers = Card(Stack(Text("Server observations", 18, false, FontWeights.SemiBold), Gap(10), Text("Configuration and current service state are separate observations. No server is started, stopped or reconfigured.", 12, true), _serviceGrid, Gap(14), _listenerText, _siteGrid));
        Register("Home", Stack(Heading("Workspace", "Recovery overview", _controller.IsDemo ? "Synthetic demonstration · no production database is touched." : "Local discovery and recovery, with explicit actions and traceable outcomes."), heroCard, metrics, Columns(Card(workflow), Card(machine)), servers));
    }
    private static StackPanel Step(string number, string title, string description)
    {
        var panel = Stack(Text(number + "  " + title, 14, false, FontWeights.SemiBold), Text(description, 12, true));
        panel.Margin = new Thickness(0, 19, 0, 0);
        ((TextBlock)panel.Children[1]).Margin = new Thickness(28, 7, 0, 0);
        return panel;
    }
    private void BuildInstallations()
    {
        _scanSummary = Text("No scan has run. Discovery stays within your selected folder and time limits.", 12, true);
        _scanSummary.Margin = new Thickness(0, 14, 0, 0);
        _installationGrid = Table("Discovered Joomla installations", 255,
            ("Installation", "Display", 1.6), ("Root folder", "RootPath", 2.5), ("State", "Status", 1));
        _installationGrid.ItemsSource = _installations;
        _installationGrid.SelectionChanged += (_, _) => InstallationChanged();
        var list = Card(Stack(Row(Action("Scan selected roots", ScanAsync, true, true), Action("Edit scope", () => Navigate("Settings"))), _scanSummary, _installationGrid));
        _installationDetail = Text("Select an installation to inspect its paths and resolve its database configuration.", 13, true);
        var detail = Card(Stack(Text("Selected installation", 18, false, FontWeights.SemiBold), Gap(14), _installationDetail,
            Row(Action("Resolve configuration", ResolveSelectedAsync, true, true), Action("Open public site", () => OpenSite(false)), Action("Open administrator", () => OpenSite(true)), Action("Check administrator URL", CheckAdministratorAsync, false, true))));
        Register("Installations", Stack(Heading("Discovery", "Joomla installations", "Each installation retains its own configuration, database and recovery context."), list, detail));
    }
    private void BuildDatabase()
    {
        _host = Input("Database host", "localhost"); _port = Input("Database port", "3306");
        _database = Input("Database name"); _prefix = Input("Joomla table prefix"); _username = Input("Database username");
        _databasePassword = Secret("Database password");
        _allowRemote = new CheckBox { Content = "Allow this explicitly selected remote database host" };
        _saveCredential = new CheckBox { Content = "Save credentials in Windows Credential Manager after a successful inspection" };
        _databaseSummary = Text("Resolve a selected installation or enter a connection override. No connection is made until you inspect.", 13, true);
        var connection = Stack(Text("Connection target", 18, false, FontWeights.SemiBold), Gap(18),
            Columns(Field("Host", _host), Field("Port", _port)),
            Columns(Field("Database", _database), Field("Table prefix", _prefix)),
            Columns(Field("Database username", _username), Field("Password", _databasePassword, "Masked in the interface. Never written to evidence.")),
            _allowRemote, _saveCredential,
            Row(Action("Inspect database", InspectDatabaseAsync, true, true), Action("Load saved credentials", LoadDatabaseCredential), Action("Forget saved credentials", ForgetDatabaseCredential)),
            Gap(18), _databaseSummary);
        _tableGrid = Table("Database table names", 240, ("Observed table", "Name", 1));
        var tables = Stack(Text("Database structure", 18, false, FontWeights.SemiBold), Text("Table names from explicit metadata inspection.", 12, true), _tableGrid,
            Row(Action("Review accounts", () => Navigate("Accounts")), Action("Preview account query", LoadAccountQuery), Action("Open phpMyAdmin", OpenPhpMyAdmin)));
        Register("Database", Stack(Heading("Connection", "Know the exact database", "Configuration values can be overridden for this session. Inspection queries are read-only."), Card(connection), Card(tables)));
        foreach (var input in new[] { _host, _port, _database, _prefix, _username }) input.TextChanged += (_, _) => InvalidateConnectionReview();
        _databasePassword.PasswordChanged += (_, _) => InvalidateConnectionReview();
        _allowRemote.Checked += (_, _) => InvalidateConnectionReview();
        _allowRemote.Unchecked += (_, _) => InvalidateConnectionReview();
    }
    private void BuildAccounts()
    {
        _accountSearch = Input("Filter accounts", ""); _accountSearch.TextChanged += (_, _) => FilterAccounts();
        _accountSummary = Text("Inspect a selected database to read accounts and group membership. Password hashes are never displayed.", 13, true);
        _accountGrid = Table("Joomla accounts", 330,
            ("ID", "Id", 0.5), ("Username", "Username", 1.1), ("Display name", "DisplayName", 1.4),
            ("Email", "Email", 1.8), ("Groups", "Groups", 1.3), ("Admin privileges", "AdministratorPrivileges", 1.3), ("Blocked", "Blocked", 0.7));
        _accountDetail = Text("Select an account to review its complete identity and state.", 12, true);
        _accountDetail.Margin = new Thickness(0, 14, 0, 0);
        _accountGrid.SelectionChanged += (_, _) => { _selectedAccount = _accountGrid.SelectedItem as AccountInfo; InvalidateRecovery(); RefreshRecoveryTarget(); RefreshAccountDetail(); };
        Register("Accounts", Stack(Heading("Identity", "Accounts & privileges", "Select by exact account ID. A group name alone is not proof of administrator access."),
            Card(Stack(Field("Find by username, email, name, group or ID", _accountSearch), _accountSummary, _accountGrid, _accountDetail,
                Row(Action("Continue to recovery", () => { if (_selectedAccount == null) throw new InvalidOperationException("Select an account first."); Navigate("Recovery"); }, true),
                Action("Inspect database", () => Navigate("Database"))))),
            Card(Stack(Text("Account interpretation", 16, false, FontWeights.SemiBold), Gap(10),
                Text("Blocked state, group membership, reset flags and administrator privileges have different meanings. Recovery changes only the approved password field. It does not silently unblock an account, change privileges or disable multifactor authentication.", 13, true)))));
    }
    private void BuildRecovery()
    {
        _recoveryTarget = Text("Select an installation and inspect its database, then choose an account.", 14, true);
        var target = Card(Stack(Text("01  Selected identity", 18, false, FontWeights.SemiBold), Gap(14), _recoveryTarget,
            Row(Action("Choose account", () => Navigate("Accounts")), Action("Open Joomla administrator", () => OpenSite(true)))));
        _fallback = new CheckBox { Content = "Use the direct database password fallback for this supported Joomla 4 or 5 account" };
        _fallbackReason = Input("Reason for direct database fallback", "", true, 70);
        _fallback.Checked += (_, _) => InvalidateRecovery();
        _fallback.Unchecked += (_, _) => InvalidateRecovery();
        _fallbackReason.TextChanged += (_, _) => InvalidateRecovery();
        var method = Card(Stack(Text("02  Recovery method", 18, false, FontWeights.SemiBold), Gap(12),
            Text("Prefer Joomla's built-in reset email or an authorized administrator session when available. The direct fallback requires Joomla 4 or 5 and a database target matching the selected installation's resolved configuration. Credential overrides are allowed; other manually selected targets remain inspection-only.", 13, true),
            _fallback, Field("Why is the fallback necessary?", _fallbackReason, "12–500 characters. Do not include passwords or other secrets.")));
        _newPassword = Secret("New account password"); _repeatPassword = Secret("Confirm new account password");
        _passwordReveal = Input("Temporarily revealed new password"); _passwordReveal.IsReadOnly = true; _passwordReveal.Visibility = Visibility.Collapsed;
        _newPassword.PasswordChanged += (_, _) => { HidePassword(); InvalidateRecovery(); };
        _repeatPassword.PasswordChanged += (_, _) => InvalidateRecovery();
        var passwords = Card(Stack(Text("03  New password", 18, false, FontWeights.SemiBold), Gap(16),
            Columns(Field("New password", _newPassword), Field("Repeat password", _repeatPassword)),
            Row(Action("Generate strong password", GeneratePassword), Action("Reveal for 10 seconds", RevealPassword)),
            Gap(10), _passwordReveal, Gap(12), Text("The password is hashed before the targeted write. No plaintext password or hash is added to evidence.", 12, true),
            Row(Action("Prepare exact recovery review", PrepareRecoveryAsync, true, true))));
        _reviewText = Readout("Exact recovery target and SQL review", 210);
        _confirmation = Input("Exact recovery confirmation text");
        _authorizedOwner = new CheckBox { Content = "I own this installation or have explicit permission to reset this selected account." };
        _confirmation.TextChanged += (_, _) => UpdateRecoveryButton();
        _authorizedOwner.Checked += (_, _) => UpdateRecoveryButton();
        _authorizedOwner.Unchecked += (_, _) => UpdateRecoveryButton();
        _applyReset = Action("Apply approved password reset", ApplyRecoveryAsync, false, true);
        _applyReset.Style = (Style)FindResource("DangerButton"); _applyReset.IsEnabled = false;
        _recoveryResult = Text("", 14);
        _reviewCard = Card(Stack(Text("04  Review & authorize", 18, false, FontWeights.SemiBold), Gap(14), _reviewText, Gap(16),
            Field("Type the exact confirmation shown above", _confirmation), _authorizedOwner,
            Row(_applyReset), Gap(14), _recoveryResult));
        _reviewCard.Visibility = Visibility.Collapsed;
        Register("Recovery", Stack(Heading("Access recovery", "One account. One reviewed change.", "No password reset runs automatically. The preview expires, and the original row is checked again before a write."),
            target, method, passwords, _reviewCard));
    }
    private void BuildSql()
    {
        _sqlEditor = Input("Read-only SQL editor", "SELECT id, name, username, email, block FROM yourprefix_users LIMIT 100", true, 140);
        _sqlEditor.FontFamily = new FontFamily("Cascadia Code, Consolas"); _sqlEditor.FontSize = 13;
        _sqlEditor.TextChanged += (_, _) => { _queryPlan = null; if (_runQuery != null) _runQuery.IsEnabled = false; };
        _sqlPreview = new RichTextBox { IsReadOnly = true, Height = 155, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Padding = new Thickness(12), BorderThickness = new Thickness(1), FontFamily = new FontFamily("Cascadia Code, Consolas"), FontSize = 12 };
        _sqlPreview.SetResourceReference(Control.BackgroundProperty, "CanvasBrush");
        _sqlPreview.SetResourceReference(Control.ForegroundProperty, "TextBrush");
        _sqlPreview.SetResourceReference(Control.BorderBrushProperty, "BorderBrush");
        AutomationProperties.SetName(_sqlPreview, "Validated SQL plan with syntax highlighting");
        _querySummary = Text("A query must pass validation and show an exact target before execution.", 12, true);
        _runQuery = Action("Run reviewed read-only query", ExecuteQueryAsync, true, true); _runQuery.IsEnabled = false;
        _queryGrid = new DataGrid { Height = 260, AutoGenerateColumns = true, Margin = new Thickness(0, 14, 0, 0) };
        AutomationProperties.SetName(_queryGrid, "Read-only SQL query result");
        Register("SQL", Stack(Heading("SQL workbench", "Inspect with a visible plan", "Restricted read-only queries. One statement, bounded results, no credential or password columns."),
            Card(Stack(Text("SQL editor", 18, false, FontWeights.SemiBold), Gap(14), _sqlEditor,
                Row(Action("Use account list query", LoadAccountQuery), Action("Validate & preview", PreviewQuery)), Gap(16),
                _sqlPreview, Row(_runQuery, Action("Copy validated SQL", CopyValidatedSql)), Gap(14), _querySummary)),
            Card(Stack(Text("Results", 18, false, FontWeights.SemiBold), Row(Action("Export results JSON", () => ExportQueryResults(true)), Action("Export results CSV", () => ExportQueryResults(false))),
                Gap(10), Text("Result exports may contain account names and email addresses. Choose their destination deliberately.", 12, true), _queryGrid))));
    }
    private void BuildAssistant()
    {
        _question = Input("Assistant question", "", true, 105);
        _assistantReply = Readout("Assistant response", 260);
        _assistantReply.Text = "Ask about installation discovery, configuration references, database connectivity, account privileges, safe recovery or the current selected target.\n\nLocal guidance works without a provider. An optional remote request always shows the exact sanitized payload for your approval.";
        _assistantStatus = Text("Local guidance is available. No provider request has been sent.", 12, true);
        _aiEnabled = new CheckBox { Content = "Enable the optional OpenAI-compatible provider" };
        _endpoint = Input("AI provider HTTPS endpoint", _controller.Settings.Ai.Endpoint);
        _model = Input("AI provider model", _controller.Settings.Ai.Model);
        _providerKey = Secret("Optional provider API key");
        _aiEnabled.IsChecked = _controller.Settings.Ai.Enabled;
        Register("Assistant", Stack(Heading("Assistance", "Understand before you act", "The assistant explains observed state. It cannot execute SQL, reset accounts or run system commands."),
            Card(Stack(Field("What would you like to understand?", _question),
                Row(Action("Ask local guide", AskLocal, true), Action("Preview provider request", SendAssistantAsync, false, true)),
                Gap(14), _assistantStatus, Gap(14), _assistantReply)),
            Card(Stack(Text("Optional provider", 18, false, FontWeights.SemiBold), _aiEnabled,
                Field("Endpoint", _endpoint, "No request is made until you approve an exact payload."),
                Field("Model", _model), Field("API key", _providerKey, "Enter a key for this product. Existing keys from other applications are never inspected."),
                Row(Action("Save provider settings", SaveProviderSettings), Action("Save key securely", SaveProviderKey), Action("Forget saved key", ForgetProviderKey)),
                Row(Action("Preview test request", TestProviderAsync, false, true), Action("Disconnect provider", DisconnectProvider))))));
    }
    private void BuildEvidence()
    {
        _evidenceGrid = Table("Local evidence history", 410,
            ("Observed at", "ObservedAt", 1.3), ("Kind", "Kind", 0.8), ("Status", "Status", 0.8), ("Summary", "Summary", 3));
        Register("Evidence", Stack(Heading("Audit trail", "Evidence, kept local", "Structured outcomes and target metadata. Passwords, password hashes and provider keys are excluded."),
            Card(Stack(Row(Action("Refresh", RefreshEvidence), Action("Export JSON", () => ExportEvidence(true)), Action("Export CSV", () => ExportEvidence(false)), Action("Delete local history", DeleteEvidence)), _evidenceGrid)),
            Card(Stack(Text("Evidence is not a backup", 16, false, FontWeights.SemiBold), Gap(10),
                Text("Exports describe observations and approved outcomes. They do not contain database backups or recoverable credentials. Export destinations are chosen explicitly.", 13, true)))));
    }
    private void BuildSettings()
    {
        var scan = _controller.Settings.Scan;
        _rootPaths = Input("Approved discovery root folders", string.Join(Environment.NewLine, scan.Roots), true, 155);
        _depth = Input("Maximum scan depth", scan.MaxDepth.ToString());
        _duration = Input("Maximum scan seconds", scan.MaxSeconds.ToString());
        _fileBudget = Input("Maximum file count", scan.MaxFiles.ToString());
        _directoryBudget = Input("Maximum directory count", scan.MaxDirectories.ToString());
        _exclusions = Input("Excluded folder names", string.Join(Environment.NewLine, scan.ExcludedDirectories), true, 115);
        var personal = Action("Add personal projects folder", AddFolder);
        Register("Settings", Stack(Heading("Preferences", "Choose the scope", "Discovery is bounded. Personal project folders are added only when you explicitly select them."),
            Card(Stack(Text("Approved folders", 18, false, FontWeights.SemiBold), Gap(12), _rootPaths,
                Row(Action("Add folder…", AddFolder), personal, Action("Restore default roots", RestoreRoots)),
                Gap(18), Columns(Field("Maximum depth", _depth, "1–12 directory levels"), Field("Time budget (seconds)", _duration, "5–120 seconds")),
                Columns(Field("File budget", _fileBudget, "1–200,000 files"), Field("Directory budget", _directoryBudget, "1–50,000 directories")),
                Field("Excluded folder names · one per line", _exclusions, "Add exclusions as needed. The default protected exclusions are always retained."),
                Text("Dependency trees, caches, credential stores, browser data and system folders are excluded. A bounded scan can be partial; absence within a scope is not workstation-wide absence.", 12, true),
                Row(Action("Save scope", SaveScope, true), Action("Discover with this scope", ScanAsync, false, true)))),
            Card(Stack(Text("Appearance & data", 18, false, FontWeights.SemiBold), Gap(10),
                Text("Switch the theme from the top bar. Saved database and provider secrets use this application's Windows Credential Manager entries. Evidence history can be exported or cleared from Evidence.", 13, true),
                Row(Action("Open evidence", () => Navigate("Evidence")), Action("Open optional provider", () => Navigate("Assistant")))))));
    }
    private static Border Gap(double height) => new() { Height = height };
}
