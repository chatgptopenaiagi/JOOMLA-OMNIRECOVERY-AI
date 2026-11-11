using System.Data;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Microsoft.Win32;
using OmniRecovery.Core;
using OmniRecovery.Infrastructure.Ai;
using OmniRecovery.Infrastructure.Database;
using OmniRecovery.Infrastructure.Recovery;
using OmniRecovery.Infrastructure.Security;

namespace OmniRecovery.Desktop;

public partial class MainWindow
{
    private void ClearConnectionForm()
    {
        _connection = null;
        _host.Text = "localhost";
        _port.Text = "3306";
        _database.Clear();
        _username.Clear();
        _prefix.Clear();
        _databasePassword.Clear();
        _allowRemote.IsChecked = false;
        _saveCredential.IsChecked = false;
        InvalidateConnectionReview();
    }
    private void InvalidateConnectionReview()
    {
        _inspection = null;
        _selectedAccount = null;
        if (_accountGrid != null) _accountGrid.ItemsSource = null;
        if (_tableGrid != null) _tableGrid.ItemsSource = null;
        if (_queryGrid != null) _queryGrid.ItemsSource = null;
        _queryPlan = null;
        if (_sqlPreview != null) _sqlPreview.Document.Blocks.Clear();
        if (_runQuery != null) _runQuery.IsEnabled = false;
        ConnectionBadge.Text = "○  Target requires inspection";
        InvalidateRecovery();
        if (_accountCount != null) _accountCount.Text = "0";
        RefreshAccountDetail();
    }
    private void RefreshAccountDetail()
    {
        if (_accountDetail == null) return;
        var account = _selectedAccount;
        _accountDetail.Text = account == null ? "Select an account to review its complete identity and state."
            : $"ID {account.Id} · {account.Username} · {account.DisplayName}\nEmail: {account.Email}\nGroups: {account.Groups}\nPrivileges: {account.AdministratorPrivileges}\nBlocked: {account.Blocked} · Require reset: {account.RequireReset} · Last visit: {account.LastVisit ?? "Not recorded"}\n{account.Notes}";
    }
    private void InvalidateRecovery()
    {
        _recoveryPreview = null;
        _recoveryService = null;
        if (_reviewCard != null) _reviewCard.Visibility = Visibility.Collapsed;
        if (_confirmation != null) _confirmation.Clear();
        if (_authorizedOwner != null) _authorizedOwner.IsChecked = false;
        UpdateRecoveryButton();
    }
    private void RefreshRecoveryTarget()
    {
        if (_recoveryTarget == null) return;
        _recoveryTarget.Text = _selectedAccount == null || _selectedInstallation == null
            ? "No account selected. Inspect a database and select an account before preparing recovery."
            : $"INSTALLATION   {_selectedInstallation.Name} · Joomla {_selectedInstallation.Version}\nDATABASE       {_connection?.Database ?? "Not inspected"}\nACCOUNT ID     {_selectedAccount.Id}\nUSERNAME       {_selectedAccount.Username}\nGROUPS         {_selectedAccount.Groups}\nPRIVILEGES     {_selectedAccount.AdministratorPrivileges}\nBLOCKED        {_selectedAccount.Blocked}";
    }
    private void GeneratePassword()
    {
        string password = _controller.Passwords.GeneratePassword();
        _newPassword.Password = password;
        _repeatPassword.Password = password;
        StatusText.Text = "A strong password was generated and remains masked.";
    }
    private void HidePassword()
    {
        _revealTimer?.Stop();
        if (_passwordReveal != null) { _passwordReveal.Clear(); _passwordReveal.Visibility = Visibility.Collapsed; }
    }
    private void RevealPassword()
    {
        if (_newPassword.Password.Length == 0) { StatusText.Text = "Enter or generate a password first."; return; }
        _passwordReveal.Text = _newPassword.Password;
        _passwordReveal.Visibility = Visibility.Visible;
        _revealTimer?.Stop();
        _revealTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(10) };
        _revealTimer.Tick += (_, _) => HidePassword();
        _revealTimer.Start();
        StatusText.Text = "Password revealed for 10 seconds. It will not be copied or logged.";
    }
    private void ValidateNewPassword()
    {
        if (_newPassword.Password.Length < 12) throw new ArgumentException("Use a new password with at least 12 characters.");
        if (Encoding.UTF8.GetByteCount(_newPassword.Password) > 72) throw new ArgumentException("This bcrypt recovery method accepts at most 72 UTF-8 bytes. Use a shorter password.");
        if (_newPassword.Password != _repeatPassword.Password) throw new ArgumentException("The two password entries do not match.");
    }
    private async Task PrepareRecoveryAsync()
    {
        await RunAsync("Preparing recovery review", async ct =>
        {
            var installation = RequireInstallation();
            if (_selectedAccount == null || _connection == null || _inspection == null) throw new InvalidOperationException("Inspect the exact database and select an account first.");
            ValidateNewPassword();
            var reason = _fallbackReason.Text.Trim();
            if (_fallback.IsChecked != true) throw new InvalidOperationException("Use Joomla's built-in recovery route, or explicitly select the direct fallback and explain why it is necessary.");
            if (reason.Length is < 12 or > 500) throw new ArgumentException("Provide a fallback reason between 12 and 500 characters.");
            HidePassword();
            _recoveryService = new RecoveryService(_controller.Repository(_connection), _controller.Passwords);
            _recoveryPreview = await _recoveryService.PreviewAsync(installation, _connection, _selectedAccount.Id, true, ct, fallbackReason: reason);
            var p = _recoveryPreview;
            _reviewText.Text = $"INSTALLATION: {p.InstallationName} · Joomla {p.JoomlaVersion}\nDATABASE: {p.Database}\nPREFIX: {p.Prefix}\nACCOUNT ID: {p.AccountId}\nUSERNAME: {p.Username}\nMETHOD: {p.Method}\nEXPIRES: {p.ExpiresAt.LocalDateTime:G}\n\nSQL PREVIEW\n{p.SqlPreview}\n\nEXACT CONFIRMATION\n{p.ConfirmationText}\n\n{string.Join("\n", p.Warnings)}";
            _confirmation.Clear();
            _authorizedOwner.IsChecked = false;
            _recoveryResult.Text = "";
            _reviewCard.Visibility = Visibility.Visible;
            AddEvidence("recovery-preview", "Prepared", $"Prepared an expiring recovery preview for account ID {p.AccountId}; no password changed.", new Dictionary<string, string> { ["database"] = p.Database, ["table_prefix"] = p.Prefix, ["account_id"] = p.AccountId.ToString(), ["joomla_version"] = p.JoomlaVersion, ["action"] = "preview_direct_password_fallback" });
            _reviewCard.BringIntoView();
        });
    }
    private void UpdateRecoveryButton()
    {
        if (_applyReset == null) return;
        _applyReset.IsEnabled = !_busy && _recoveryPreview != null && _recoveryPreview.ExpiresAt > DateTimeOffset.UtcNow &&
            _authorizedOwner?.IsChecked == true && _confirmation?.Text == _recoveryPreview.ConfirmationText;
    }
    private async Task ApplyRecoveryAsync()
    {
        if (_recoveryPreview == null || _recoveryService == null || _connection == null) throw new InvalidOperationException("Prepare a fresh recovery preview.");
        if (_authorizedOwner.IsChecked != true || _confirmation.Text != _recoveryPreview.ConfirmationText)
            throw new InvalidOperationException("Owner authorization and exact confirmation are required.");
        ValidateNewPassword();
        var preview = _recoveryPreview;
        var service = _recoveryService;
        var connection = _connection.Copy();
        var confirmation = _confirmation.Text;
        if (!(_smokeTest && _controller.IsDemo) && MessageBox.Show($"Reset only this account?\n\nDatabase: {preview.Database}\nAccount ID: {preview.AccountId}\nUsername: {preview.Username}\n\nThe selected password field will be changed. Other account settings stay as they are.",
            "Apply approved recovery", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes) return;
        await RunAsync("Applying approved account recovery", async ct =>
        {
            var outcome = await service.ExecuteAsync(connection, preview, confirmation, _newPassword.Password, _fallback.IsChecked == true, ct);
            _lastRecoveryOutcome = outcome;
            _recoveryResult.Text = $"{(outcome.Success ? "Recovery completed" : "Recovery did not complete")}\n{outcome.Message}\nAffected rows: {outcome.AffectedRows} · Record verified: {outcome.RecordVerified}";
            _recoveryResult.SetResourceReference(System.Windows.Controls.TextBlock.ForegroundProperty, outcome.Success ? "SuccessBrush" : "WarningBrush");
            AddEvidence("recovery", outcome.Outcome, $"Approved account ID {preview.AccountId}: {outcome.AffectedRows} affected row(s); post-write verification={outcome.RecordVerified}.",
                new Dictionary<string, string> { ["database"] = preview.Database, ["table_prefix"] = preview.Prefix, ["account_id"] = preview.AccountId.ToString(), ["affected_rows"] = outcome.AffectedRows.ToString(), ["record_verified"] = outcome.RecordVerified.ToString(), ["joomla_version"] = preview.JoomlaVersion, ["action"] = "direct_password_fallback" });
            _recoveryPreview = null;
            _recoveryService = null;
            HidePassword();
            _newPassword.Clear();
            _repeatPassword.Clear();
            _confirmation.Clear();
            _authorizedOwner.IsChecked = false;
            // PasswordChanged invalidates the form; keep the outcome visibly available.
            _reviewCard.Visibility = Visibility.Visible;
            _applyReset.IsEnabled = false;
        });
    }

    private void LoadAccountQuery()
    {
        if (_connection == null || _inspection == null) throw new InvalidOperationException("Inspect the exact database target first.");
        _queryPlan = SqlIntelligence.AccountListPlan(_connection);
        _sqlEditor.Text = _queryPlan.Sql;
        // Editing resets the plan; rebuild it from the trusted template.
        _queryPlan = SqlIntelligence.AccountListPlan(_connection);
        _querySource = _sqlEditor.Text;
        ShowQueryPlan();
        Navigate("SQL");
    }
    private void PreviewQuery()
    {
        if (_connection == null || _inspection == null) throw new InvalidOperationException("Inspect a database before reviewing a custom query.");
        _queryPlan = SqlIntelligence.CreatePlan(_sqlEditor.Text, _connection);
        _querySource = _sqlEditor.Text;
        ShowQueryPlan();
    }
    private void ShowQueryPlan()
    {
        if (_queryPlan == null) return;
        RenderQueryPreview();
        _runQuery.IsEnabled = !_busy && _queryPlan.ReadOnly;
        _querySummary.Text = "Preview ready. Execution requires the separate Run button.";
    }
    private void RenderQueryPreview()
    {
        if (_queryPlan == null) return;
        _sqlPreview.Document.Blocks.Clear();
        var metadata = new Paragraph(new Run($"PURPOSE: {_queryPlan.Purpose}\nDATABASE: {_queryPlan.Database}\nTABLES: {string.Join(", ", _queryPlan.Tables)}\nREAD ONLY: {_queryPlan.ReadOnly}")) { Margin = new Thickness(0,0,0,10) };
        _sqlPreview.Document.Blocks.Add(metadata);
        var sql = _queryPlan.Sql;
        var paragraph = new Paragraph { Margin = new Thickness(0) };
        var pattern = @"\b(?:SELECT|FROM|WHERE|ORDER|BY|LIMIT|JOIN|LEFT|INNER|ON|AS|AND|OR|IN|IS|NULL|DESC|ASC|COUNT|GROUP)\b|'(?:''|[^'])*'|\b\d+\b";
        var offset = 0;
        foreach (Match match in Regex.Matches(sql, pattern, RegexOptions.IgnoreCase))
        {
            if (match.Index > offset) paragraph.Inlines.Add(new Run(sql[offset..match.Index]));
            var color = match.Value.StartsWith("'") ? (_dark ? "#52D6AE" : "#087A5A") : char.IsDigit(match.Value[0]) ? (_dark ? "#F8BD65" : "#9B630D") : (_dark ? "#A89AFF" : "#6755DB");
            paragraph.Inlines.Add(new Run(match.Value) { Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(color)), FontWeight = FontWeights.SemiBold });
            offset = match.Index + match.Length;
        }
        if (offset < sql.Length) paragraph.Inlines.Add(new Run(sql[offset..]));
        _sqlPreview.Document.Blocks.Add(paragraph);
    }
    private void CopyValidatedSql()
    {
        if (_queryPlan == null || _querySource != _sqlEditor.Text) throw new InvalidOperationException("Validate the current SQL first.");
        Clipboard.SetText(_queryPlan.Sql);
        StatusText.Text = "Validated SQL copied to the clipboard by request.";
    }
    private void ExportQueryResults(bool json)
    {
        if (_queryGrid.ItemsSource is not DataView view) throw new InvalidOperationException("Run a reviewed query before exporting results.");
        var dialog = new SaveFileDialog { Title = "Export query results — may contain account identity data", Filter = json ? "JSON results (*.json)|*.json" : "CSV results (*.csv)|*.csv",
            FileName = "omnirecovery-query-" + DateTime.Now.ToString("yyyyMMdd-HHmmss"), DefaultExt = json ? ".json" : ".csv", AddExtension = true, OverwritePrompt = true };
        if (dialog.ShowDialog(this) != true) return;
        WriteQueryResults(dialog.FileName, json, view);
        StatusText.Text = $"{view.Count} displayed row(s) exported to the selected destination.";
    }
    private void WriteQueryResults(string path, bool json, DataView view)
    {
        var columns = view.Table!.Columns.Cast<DataColumn>().Select(c => c.ColumnName).ToArray();
        var rows = view.Cast<DataRowView>().Select(row => columns.Select(c => row[c]?.ToString() ?? "").ToArray()).ToArray();
        if (json) File.WriteAllText(path, JsonSerializer.Serialize(new { exportedAt = DateTimeOffset.UtcNow, database = _connection?.Database, columns, rows }, new JsonSerializerOptions { WriteIndented = true }));
        else
        {
            var lines = new[] { string.Join(",", columns.Select(CsvCell)) }.Concat(rows.Select(row => string.Join(",", row.Select(CsvCell))));
            File.WriteAllText(path, string.Join("\r\n", lines), new UTF8Encoding(true));
        }
    }
    private static string CsvCell(string value)
    {
        var trimmed = value.TrimStart();
        if ((trimmed.Length > 0 && "=+-@".Contains(trimmed[0])) || (value.Length > 0 && char.IsControl(value[0]))) value = "'" + value;
        return "\"" + value.Replace("\"", "\"\"") + "\"";
    }
    private async Task ExecuteQueryAsync()
    {
        await RunAsync("Executing reviewed read-only query", async ct =>
        {
            if (_connection == null || _inspection == null || _queryPlan == null || _querySource != _sqlEditor.Text) throw new InvalidOperationException("Inspect the target and validate the current SQL text again.");
            var result = await _controller.Repository(_connection).ExecuteReadOnlyAsync(_connection, _queryPlan, ct);
            var data = new DataTable();
            for (int i = 0; i < result.Columns.Count; i++)
            {
                var name = string.IsNullOrWhiteSpace(result.Columns[i]) ? $"Column {i + 1}" : result.Columns[i];
                if (data.Columns.Contains(name)) name += " " + i;
                data.Columns.Add(name, typeof(string));
            }
            foreach (var values in result.Rows)
            {
                var row = data.NewRow();
                for (int i = 0; i < result.Columns.Count; i++)
                {
                    var raw = i < values.Count ? values[i] : null;
                    row[i] = Regex.IsMatch(result.Columns[i], "password|passwd|secret|token|credential", RegexOptions.IgnoreCase)
                        ? "[hidden]" : raw is byte[] ? "[binary data]" : raw?.ToString() ?? "";
                }
                data.Rows.Add(row);
            }
            _queryGrid.ItemsSource = data.DefaultView;
            _querySummary.Text = $"{result.Rows.Count} row(s) returned{(result.Truncated ? " · results truncated at safety limit" : "")}. No database content was modified.";
            AddEvidence("sql", "ReadOnlyCompleted", $"Reviewed read-only query returned {result.Rows.Count} row(s); truncated={result.Truncated}.", new Dictionary<string, string> { ["database"] = _connection.Database });
        });
    }
    private void LoadDatabaseCredential()
    {
        if (_controller.IsDemo) { StatusText.Text = "Saved credentials are unavailable in synthetic demo mode."; return; }
        var connection = ReadConnection();
        var stored = _controller.Credentials.Read("database-" + connection.Id);
        if (stored == null) { StatusText.Text = "No saved credential exists for this exact target."; return; }
        _username.Text = stored.Value.Username;
        _databasePassword.Password = stored.Value.Secret;
        StatusText.Text = "Saved credentials loaded into masked fields. Connect explicitly to verify.";
    }
    private void ForgetDatabaseCredential()
    {
        if (_controller.IsDemo) { StatusText.Text = "Synthetic demo does not alter saved credentials."; return; }
        var connection = ReadConnection();
        if (MessageBox.Show("Delete this application's saved credential for the selected database target?", "Forget saved credential",
            MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes) return;
        _controller.Credentials.Delete("database-" + connection.Id);
        _databasePassword.Clear();
        StatusText.Text = "Saved credential deleted. Existing Joomla configuration was not changed.";
    }
    private void AddFolder()
    {
        var dialog = new OpenFolderDialog { Title = "Choose an approved Joomla or project folder", Multiselect = false };
        if (dialog.ShowDialog(this) != true) return;
        var paths = _rootPaths.Text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
        if (!paths.Contains(dialog.FolderName, StringComparer.OrdinalIgnoreCase)) paths.Add(dialog.FolderName);
        _rootPaths.Text = string.Join(Environment.NewLine, paths);
    }
    private void RestoreRoots()
    {
        var defaults = new ScanOptions();
        _rootPaths.Text = string.Join(Environment.NewLine, defaults.Roots);
        _depth.Text = defaults.MaxDepth.ToString();
        _duration.Text = defaults.MaxSeconds.ToString();
        _fileBudget.Text = defaults.MaxFiles.ToString();
        _directoryBudget.Text = defaults.MaxDirectories.ToString();
        _exclusions.Text = string.Join(Environment.NewLine, defaults.ExcludedDirectories);
    }
    private void SaveScope()
    {
        _controller.Settings.Scan = ReadScanOptions();
        _exclusions.Text = string.Join(Environment.NewLine, _controller.Settings.Scan.ExcludedDirectories);
        _controller.Settings.DarkTheme = _dark;
        _controller.SaveSettings();
        StatusText.Text = "Discovery scope saved. No scan was started.";
    }
    private void ExportEvidence(bool json)
    {
        var dialog = new SaveFileDialog { Title = "Export local evidence", Filter = json ? "JSON evidence (*.json)|*.json" : "CSV evidence (*.csv)|*.csv",
            FileName = "omnirecovery-evidence-" + DateTime.Now.ToString("yyyyMMdd-HHmmss"), AddExtension = true, DefaultExt = json ? ".json" : ".csv", OverwritePrompt = true };
        if (dialog.ShowDialog(this) != true) return;
        if (json) _controller.Evidence.ExportJson(dialog.FileName); else _controller.Evidence.ExportCsv(dialog.FileName);
        StatusText.Text = "Evidence exported to the selected destination.";
    }
    private void DeleteEvidence()
    {
        if (MessageBox.Show("Delete this application's local evidence history? Previously exported files will remain.", "Delete evidence history",
            MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes) return;
        _controller.Evidence.DeleteAll();
        RefreshEvidence(); RefreshCounts();
        StatusText.Text = "Local evidence history deleted.";
    }
    private void AskLocal()
    {
        _assistantReply.Text = LocalAssistant.Answer(_question.Text, _selectedInstallation, _inspection);
        _assistantStatus.Text = "Local guidance · no network request · no action executed";
    }
    private AiProviderSettings ReadProviderSettings()
    {
        return new AiProviderSettings { Enabled = _aiEnabled.IsChecked == true, Provider = "OpenAI-compatible", Endpoint = _endpoint.Text.Trim(), Model = _model.Text.Trim() };
    }
    private void SaveProviderSettings()
    {
        _controller.Settings.Ai = ReadProviderSettings();
        _controller.SaveSettings();
        _assistantStatus.Text = "Provider preferences saved. No connection was made.";
    }
    private void DisconnectProvider()
    {
        _aiEnabled.IsChecked = false;
        _providerKey.Clear();
        _controller.Settings.Ai = ReadProviderSettings();
        _controller.SaveSettings();
        _assistantStatus.Text = "Provider disabled. The unsaved key is cleared. Use Forget saved key to remove a stored credential.";
    }
    private void SaveProviderKey()
    {
        if (_controller.IsDemo) { _assistantStatus.Text = "Synthetic demo does not store provider credentials."; return; }
        if (string.IsNullOrWhiteSpace(_providerKey.Password)) throw new ArgumentException("Enter a provider key to save.");
        _controller.Credentials.Save("ai-provider", "api-key", _providerKey.Password);
        _providerKey.Clear();
        _assistantStatus.Text = "Provider key saved in this application's Windows Credential Manager entry.";
    }
    private void ForgetProviderKey()
    {
        if (_controller.IsDemo) { _assistantStatus.Text = "Synthetic demo does not alter saved provider credentials."; return; }
        if (MessageBox.Show("Delete this application's saved AI provider key?", "Forget provider key",
            MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes) return;
        _controller.Credentials.Delete("ai-provider"); _providerKey.Clear();
        _assistantStatus.Text = "Saved provider key deleted.";
    }
    private Task SendAssistantAsync() => SendProviderAsync(false);
    private Task TestProviderAsync() => SendProviderAsync(true);
    private async Task SendProviderAsync(bool test)
    {
        if (_controller.IsDemo) { _assistantStatus.Text = "Synthetic demo never sends provider requests. Use the local guide."; return; }
        var settings = ReadProviderSettings();
        if (!settings.Enabled) throw new InvalidOperationException("Explicitly enable the optional provider first.");
        var question = test ? "Reply only with: Connection verified." : _question.Text.Trim();
        if (string.IsNullOrWhiteSpace(question)) throw new ArgumentException("Enter a question first.");
        var context = new AiTechnicalContext
        {
            JoomlaVersion = _selectedInstallation?.Version ?? "Not selected",
            DatabaseStatus = _inspection?.Status.ToString() ?? "Not tested",
            DatabaseEngine = _connection?.Engine ?? "Not observed",
            ApacheStatus = _system?.Services.FirstOrDefault(s => s.Name.Contains("apache", StringComparison.OrdinalIgnoreCase))?.Status ?? "Not observed",
            PhpVersion = _system?.Tools.FirstOrDefault(t => t.Name.Contains("php", StringComparison.OrdinalIgnoreCase))?.Version ?? "Not observed"
        };
        var assistant = _controller.Ai;
        var disclosure = assistant.Prepare(settings, question, context);
        if (!ConfirmDisclosure(test ? "Review provider test request" : "Review exact assistant request",
            "Destination: " + disclosure.Endpoint + "\n\nOnly the payload below is sent. This is a model request and may use provider credits. No database rows, account identities, credentials or configuration contents are attached.",
            disclosure.JsonPreview, "Approve & send once")) return;
        await RunAsync(test ? "Testing optional provider" : "Requesting assistant guidance", async ct =>
        {
            var key = _providerKey.Password;
            if (string.IsNullOrWhiteSpace(key)) key = _controller.Credentials.Read("ai-provider")?.Secret ?? "";
            _assistantReply.Text = await assistant.SendAsync(settings, disclosure, key, true, ct);
            _assistantStatus.Text = "Provider response · advisory text only · no action executed";
            AddEvidence("assistant", "ResponseReceived", "Explicitly approved sanitized technical request completed; prompt and response content omitted.");
        });
    }
    private bool ConfirmDisclosure(string title, string explanation, string payload, string approve)
    {
        var dialog = new Window { Owner = this, Title = title, Width = 820, Height = 670, MinWidth = 600, MinHeight = 450,
            WindowStartupLocation = WindowStartupLocation.CenterOwner, ResizeMode = ResizeMode.CanResize, FontFamily = FontFamily, FontSize = 14 };
        dialog.Resources.MergedDictionaries.Add(Resources);
        dialog.SetResourceReference(Window.BackgroundProperty, "CanvasBrush");
        dialog.SetResourceReference(Window.ForegroundProperty, "TextBrush");
        var grid = new Grid { Margin = new Thickness(26) };
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        var heading = Stack(Text(title, 22, false, FontWeights.SemiBold), Gap(12), Text(explanation, 13, true), Gap(18));
        grid.Children.Add(heading);
        var preview = Readout("Exact outgoing sanitized JSON payload", double.NaN); preview.Text = payload;
        Grid.SetRow(preview, 1); grid.Children.Add(preview);
        var cancel = new Button { Content = "Cancel", IsCancel = true, IsDefault = true };
        cancel.Click += (_, _) => dialog.DialogResult = false;
        var confirm = new Button { Content = approve, Style = (Style)FindResource("PrimaryButton") };
        confirm.Click += (_, _) => dialog.DialogResult = true;
        var buttons = Row(cancel, confirm); buttons.HorizontalAlignment = HorizontalAlignment.Right;
        Grid.SetRow(buttons, 2); grid.Children.Add(buttons);
        dialog.Content = grid;
        return dialog.ShowDialog() == true;
    }

    private async Task RunSmokeAsync()
    {
        var results = new List<object>();
        string root = AppContext.BaseDirectory;
        for (var p = new DirectoryInfo(root); p != null; p = p.Parent)
            if (File.Exists(Path.Combine(p.FullName, "ENGINEERING-CHECKPOINT.md"))) { root = p.FullName; break; }
        var output = Path.Combine(root, "artifacts", "desktop-smoke-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss-fff"));
        Directory.CreateDirectory(output);
        try
        {
            if (!_controller.IsDemo) throw new InvalidOperationException("GUI smoke requires synthetic mode.");
            SetTheme(true);
            _dark = true;
            await InspectDatabaseAsync();
            // Exercise stale-target invalidation using only in-memory synthetic configuration.
            var alternative = _installations[1];
            var savedConfiguration = alternative.Configuration;
            alternative.Configuration = null;
            _databasePassword.Password = "SyntheticStaleFieldProbe";
            _installationGrid.SelectedIndex = 1;
            var staleTargetCleared = _connection == null && _inspection == null && _queryPlan == null && _recoveryPreview == null
                && _database.Text.Length == 0 && _username.Text.Length == 0 && _databasePassword.Password.Length == 0;
            alternative.Configuration = savedConfiguration;
            if (!staleTargetCleared) throw new InvalidOperationException("Unresolved installation retained a previous connection or secret.");
            _installationGrid.SelectedIndex = 0;
            await InspectDatabaseAsync();
            if (_accountGrid.Items.Count > 0) _accountGrid.SelectedIndex = 0;
            if (_connection != null) { LoadAccountQuery(); await ExecuteQueryAsync(); }
            if (_queryGrid.ItemsSource is not DataView queryRows || queryRows.Count != 3) throw new InvalidOperationException("Synthetic read-only query did not return the three fixture accounts.");
            WriteQueryResults(Path.Combine(output, "synthetic-query-results.json"), true, queryRows);
            WriteQueryResults(Path.Combine(output, "synthetic-query-results.csv"), false, queryRows);
            foreach (var formula in new[] { "=1+1", "+SUM(A1)", "-1+2", "@test", "  =1", "\tplain" })
                if (!CsvCell(formula).StartsWith("\"'", StringComparison.Ordinal)) throw new InvalidOperationException("CSV formula protection failed.");
            _fallback.IsChecked = true;
            _fallbackReason.Text = "Synthetic GUI smoke validation: no live Joomla deployment is used.";
            GeneratePassword();
            await PrepareRecoveryAsync();
            if (_recoveryPreview == null) throw new InvalidOperationException("Recovery preview was not produced.");
            _confirmation.Text = _recoveryPreview.ConfirmationText;
            _authorizedOwner.IsChecked = true;
            await ApplyRecoveryAsync();
            if (_lastRecoveryOutcome?.Success != true || !_lastRecoveryOutcome.RecordVerified || _lastRecoveryOutcome.AffectedRows != 1)
                throw new InvalidOperationException("Synthetic recovery did not produce a verified one-row outcome.");
            _question.Text = "How should I recover an administrator account safely?";
            AskLocal();
            foreach (var page in _pages.Keys)
            {
                Navigate(page);
                results.Add(new { page, rendered = true, screenshot = await CaptureSmokePageAsync(output, page) });
            }
            Navigate("Recovery");
            PageScroller.ScrollToBottom();
            results.Add(new { page = "Recovery-outcome", rendered = true, screenshot = await CaptureSmokePageAsync(output, "Recovery-outcome") });
            _dark = false;
            SetTheme(false);
            foreach (var page in new[] { "Home", "Accounts", "SQL" })
            {
                Navigate(page);
                results.Add(new { page = page + "-light", rendered = true, screenshot = await CaptureSmokePageAsync(output, page + "-light") });
            }
            Width = 1120; Height = 780;
            _dark = true;
            SetTheme(true);
            foreach (var page in new[] { "Assistant", "Settings", "Installations" })
            {
                Navigate(page);
                await Dispatcher.InvokeAsync(() => UpdateLayout(), DispatcherPriority.Render);
                PageScroller.ScrollToBottom();
                results.Add(new { page = page + "-compact", rendered = true, screenshot = await CaptureSmokePageAsync(output, page + "-compact") });
            }
            var report = new { success = true, synthetic = _controller.IsDemo, productionDatabaseTouched = false, syntheticPasswordResetExecuted = true,
                resetAffectedRows = _lastRecoveryOutcome.AffectedRows, resetRecordVerified = _lastRecoveryOutcome.RecordVerified,
                unresolvedSelectionClearedTargetAndCredentials = staleTargetCleared, readOnlyQueryRows = queryRows.Count,
                queryExportsJsonAndCsv = true, csvFormulaProtectionChecked = true,
                completedAt = DateTimeOffset.UtcNow, installations = _installations.Count, accounts = _inspection?.Accounts.Count ?? 0, pages = results };
            File.WriteAllText(Path.Combine(output, "smoke-result.json"), JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
            Application.Current.Shutdown(0);
        }
        catch (Exception ex)
        {
            File.WriteAllText(Path.Combine(output, "smoke-result.json"), JsonSerializer.Serialize(new { success = false, error = ex.GetType().Name, message = SafeMessage(SecretSafety.Error(ex)), pages = results }));
            Application.Current.Shutdown(2);
        }
    }
    private async Task<string> CaptureSmokePageAsync(string output, string name)
    {
        await Dispatcher.InvokeAsync(() => UpdateLayout(), DispatcherPriority.Render);
        await Task.Delay(180);
        var visual = (FrameworkElement)Content;
        var bitmap = new RenderTargetBitmap(Math.Max(1, (int)visual.ActualWidth), Math.Max(1, (int)visual.ActualHeight), 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(visual);
        var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
        var image = Path.Combine(output, name + ".png");
        using var stream = new FileStream(image, FileMode.CreateNew, FileAccess.Write);
        encoder.Save(stream);
        return image;
    }
}
