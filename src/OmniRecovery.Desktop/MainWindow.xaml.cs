using System.Collections.ObjectModel;
using System.Data;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Microsoft.Win32;
using OmniRecovery.Core;
using OmniRecovery.Infrastructure.Services;
using OmniRecovery.Infrastructure.Database;
using OmniRecovery.Infrastructure.Recovery;
using OmniRecovery.Infrastructure.Ai;
using OmniRecovery.Infrastructure.Security;
using OmniRecovery.Infrastructure.Discovery;

namespace OmniRecovery.Desktop;

public partial class MainWindow : Window
{
    private readonly ApplicationController _controller;
    private readonly bool _smokeTest;
    private readonly Dictionary<string, FrameworkElement> _pages = [];
    private readonly ObservableCollection<JoomlaInstallation> _installations = [];
    private readonly List<Button> _operationButtons = [];
    private CancellationTokenSource? _operation;
    private bool _busy;
    private bool _dark = true;
    private JoomlaInstallation? _selectedInstallation;
    private ConnectionSettings? _connection;
    private DatabaseInspection? _inspection;
    private SystemSnapshot? _system;
    private AccountInfo? _selectedAccount;
    private RecoveryPreview? _recoveryPreview;
    private RecoveryService? _recoveryService;
    private RecoveryOutcome? _lastRecoveryOutcome;
    private QueryPlan? _queryPlan;
    private string _querySource = "";
    private TextBlock _installationCount = null!, _configuredCount = null!, _accountCount = null!, _evidenceCount = null!;
    private TextBlock _homeContext = null!, _scanSummary = null!, _installationDetail = null!, _databaseSummary = null!, _accountSummary = null!, _recoveryTarget = null!, _recoveryResult = null!, _querySummary = null!, _assistantStatus = null!;
    private TextBox _rootPaths = null!, _depth = null!, _duration = null!;
    private TextBox _fileBudget = null!, _directoryBudget = null!, _exclusions = null!;
    private TextBlock _accountDetail = null!;
    private TextBox _host = null!, _port = null!, _database = null!, _username = null!, _prefix = null!;
    private PasswordBox _databasePassword = null!, _newPassword = null!, _repeatPassword = null!, _providerKey = null!;
    private CheckBox _allowRemote = null!, _saveCredential = null!, _fallback = null!, _authorizedOwner = null!, _aiEnabled = null!;
    private TextBox _accountSearch = null!, _fallbackReason = null!, _confirmation = null!, _passwordReveal = null!, _reviewText = null!;
    private TextBox _sqlEditor = null!, _question = null!, _assistantReply = null!, _endpoint = null!, _model = null!;
    private RichTextBox _sqlPreview = null!;
    private DataGrid _installationGrid = null!, _accountGrid = null!, _tableGrid = null!, _queryGrid = null!, _evidenceGrid = null!, _toolGrid = null!;
    private DataGrid _serviceGrid = null!, _siteGrid = null!;
    private TextBlock _listenerText = null!;
    private Button _applyReset = null!, _runQuery = null!;
    private Border _reviewCard = null!;
    private DispatcherTimer? _revealTimer;

    public MainWindow(ApplicationController controller, bool smokeTest = false)
    {
        _controller = controller;
        _smokeTest = smokeTest;
        InitializeComponent();
        _dark = _controller.Settings.DarkTheme;
        SetTheme(_dark);
        BuildPages();
        ModeText.Text = controller.IsDemo ? "Synthetic demo · isolated fixture data" : "Actions start only when you choose.";
        Navigate("Home");
        RefreshEvidence();
        Loaded += async (_, _) =>
        {
            if (_controller.IsDemo) await RunAsync("Preparing synthetic demonstration", async ct =>
            {
                var demo = await _controller.CreateDemoAsync();
                _system = _controller.LastSystemSnapshot;
                if (_system != null) ShowSystemSnapshot(_system);
                SetInstallations(demo, "Synthetic fixture loaded. No production installation was scanned.");
                if (_installations.Count > 0)
                {
                    _installationGrid.SelectedIndex = 0;
                    ApplyConfiguration(_installations[0]);
                    if (_connection != null)
                    {
                        _inspection = await _controller.Repository(_connection).InspectAsync(_connection, ct);
                        ApplyInspection(_inspection);
                    }
                }
            });
            if (_smokeTest) await RunSmokeAsync();
        };
        Closing += (_, _) =>
        {
            _operation?.Cancel();
            _revealTimer?.Stop();
            _databasePassword.Clear();
            _newPassword.Clear();
            _repeatPassword.Clear();
            _providerKey.Clear();
            _passwordReveal.Clear();
        };
    }

    private void Navigate_Click(object sender, RoutedEventArgs e)
    {
        if (sender is ToggleButton button && button.Tag is string page) Navigate(page);
    }
    private void Navigate(string page)
    {
        foreach (var pair in _pages) pair.Value.Visibility = pair.Key == page ? Visibility.Visible : Visibility.Collapsed;
        foreach (var button in Navigation.Children.OfType<ToggleButton>()) button.IsChecked = Equals(button.Tag, page);
        Breadcrumb.Text = "Workspace  /  " + (page == "Home" ? "Overview" : page == "SQL" ? "SQL workbench" : page);
        PageScroller.ScrollToTop();
        if (page == "Evidence") RefreshEvidence();
        if (page == "Recovery") RefreshRecoveryTarget();
    }
    private void Theme_Click(object sender, RoutedEventArgs e)
    {
        _dark = !_dark;
        SetTheme(_dark);
        _controller.Settings.DarkTheme = _dark;
        try { _controller.SaveSettings(); } catch { StatusText.Text = "Appearance changed for this session; preferences could not be saved."; }
    }
    private void SetTheme(bool dark)
    {
        var colors = dark
            ? new[] { "#0C111D", "#101725", "#151E2E", "#1C283B", "#2A3850", "#EDF2FB", "#A2B1C8", "#8070FF", "#52D6AE", "#F8BD65", "#EF8191" }
            : new[] { "#F4F6FB", "#FFFFFF", "#FFFFFF", "#EAF0F8", "#D8E0ED", "#18253C", "#52647F", "#6755DB", "#087A5A", "#9B630D", "#AD334E" };
        var keys = new[] { "CanvasBrush", "SidebarBrush", "CardBrush", "RaisedBrush", "BorderBrush", "TextBrush", "MutedBrush", "AccentBrush", "SuccessBrush", "WarningBrush", "DangerBrush" };
        for (int i = 0; i < keys.Length; i++) Resources[keys[i]] = new SolidColorBrush((Color)ColorConverter.ConvertFromString(colors[i]));
        if (_sqlPreview != null && _queryPlan != null) RenderQueryPreview();
    }
    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        _operation?.Cancel();
        StatusText.Text = "Cancellation requested. Waiting for the current bounded operation.";
    }
    private async Task RunAsync(string label, Func<CancellationToken, Task> action)
    {
        if (_busy) { StatusText.Text = "Finish or cancel the current operation first."; return; }
        _busy = true;
        PageHost.IsEnabled = false;
        _operation = new CancellationTokenSource();
        foreach (var b in _operationButtons) b.IsEnabled = false;
        CancelButton.Visibility = BusyProgress.Visibility = Visibility.Visible;
        StatusText.Text = label + "…";
        try
        {
            await action(_operation.Token);
            if (!_operation.IsCancellationRequested) StatusText.Text = label + " completed.";
        }
        catch (OperationCanceledException) { StatusText.Text = label + " cancelled."; }
        catch (Exception ex)
        {
            StatusText.Text = label + " could not be completed.";
            AddEvidence("operation", "Error", label + " failed (" + ex.GetType().Name + ").");
            if (_smokeTest) throw;
            MessageBox.Show(SafeMessage(SecretSafety.Error(ex)), label, MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            _operation.Dispose();
            _operation = null;
            _busy = false;
            PageHost.IsEnabled = true;
            foreach (var b in _operationButtons) b.IsEnabled = true;
            CancelButton.Visibility = BusyProgress.Visibility = Visibility.Collapsed;
            UpdateRecoveryButton();
            _runQuery.IsEnabled = _queryPlan != null && _sqlEditor.Text == _querySource;
            RefreshEvidence();
            RefreshCounts();
        }
    }
    private string SafeMessage(string message)
    {
        foreach (var secret in new[] { _databasePassword?.Password, _newPassword?.Password, _repeatPassword?.Password, _providerKey?.Password, _connection?.Password })
            if (!string.IsNullOrEmpty(secret) && secret.Length >= 3) message = message.Replace(secret, "[hidden]", StringComparison.Ordinal);
        message = Regex.Replace(message, @"(?i)(password|pwd|token|api[_-]?key|secret)\s*[=:]\s*[^;\s]+", "$1=[hidden]");
        return message.Length > 1200 ? message[..1200] : message;
    }

    private ScanOptions ReadScanOptions()
    {
        var roots = _rootPaths.Text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (roots.Count == 0 || roots.Any(p => !Path.IsPathFullyQualified(p))) throw new ArgumentException("Choose at least one absolute folder path in Settings.");
        if (!int.TryParse(_depth.Text, out var depth) || depth is < 1 or > 12) throw new ArgumentException("Scan depth must be between 1 and 12.");
        if (!int.TryParse(_duration.Text, out var seconds) || seconds is < 5 or > 120) throw new ArgumentException("Scan time must be between 5 and 120 seconds.");
        if (!int.TryParse(_fileBudget.Text, out var files) || files is < 1 or > 200000) throw new ArgumentException("File budget must be between 1 and 200,000.");
        if (!int.TryParse(_directoryBudget.Text, out var directories) || directories is < 1 or > 50000) throw new ArgumentException("Directory budget must be between 1 and 50,000.");
        var extra = _exclusions.Text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (extra.Any(x => x.Length > 100 || x.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)) throw new ArgumentException("Exclusions must be folder names, one per line, without path separators.");
        return new ScanOptions { Roots = roots, MaxDepth = depth, MaxSeconds = seconds, MaxFiles = files, MaxDirectories = directories,
            ExcludedDirectories = new ScanOptions().ExcludedDirectories.Concat(extra).Distinct(StringComparer.OrdinalIgnoreCase).ToList() };
    }
    private async Task ScanAsync()
    {
        await RunAsync("Discovering Joomla installations", async ct =>
        {
            var options = ReadScanOptions();
            Navigate("Installations");
            if (_controller.IsDemo)
            {
                SetInstallations(await _controller.CreateDemoAsync(), "Synthetic demo fixture refreshed. No live folders scanned.");
                return;
            }
            var progress = new Progress<ScanProgress>(p => StatusText.Text = $"{p.Directories:N0} folders · {p.Files:N0} files · {p.Installations} installations — {p.Message}");
            var result = await _controller.ScanAsync(options, progress, ct);
            _system = _controller.LastSystemSnapshot;
            if (_system != null) ShowSystemSnapshot(_system);
            SetInstallations(result.Installations, $"{result.DirectoriesVisited:N0} folders · {result.FilesVisited:N0} files · {(result.Cancelled ? "cancelled" : result.Complete ? "scope completed" : "bounded / partial coverage")} · {result.FinishedAt.LocalDateTime:t}");
            AddEvidence("discovery", result.Complete ? "Completed" : result.Cancelled ? "Cancelled" : "Partial", $"Scoped scan found {result.Installations.Count} installation(s); {result.DirectoriesVisited} directories and {result.FilesVisited} files visited.");
        });
    }
    private void SetInstallations(IReadOnlyList<JoomlaInstallation> items, string summary)
    {
        _installations.Clear();
        foreach (var item in items) _installations.Add(item);
        _scanSummary.Text = summary;
        RefreshCounts();
        if (_installations.Count == 0) _installationDetail.Text = "No Joomla installation found in this bounded scope. Review roots and coverage before widening the scan.";
    }
    private void InstallationChanged()
    {
        if (_busy && _installationGrid.SelectedItem == null) return;
        _selectedInstallation = _installationGrid.SelectedItem as JoomlaInstallation;
        _inspection = null;
        _connection = null;
        _selectedAccount = null;
        _recoveryPreview = null;
        _accountGrid.ItemsSource = null;
        _tableGrid.ItemsSource = null;
        ClearConnectionForm();
        _newPassword.Clear();
        _repeatPassword.Clear();
        ConnectionBadge.Text = "○  Not connected";
        _databaseSummary.Text = "Resolve the selected configuration, then explicitly inspect its database.";
        if (_selectedInstallation is null) { RefreshCounts(); return; }
        var i = _selectedInstallation;
        _installationDetail.Text = $"JOOMLA {i.Version}  ·  {i.Status}\n\n{i.RootPath}\n\nConfiguration: {i.ConfigurationPath}\nPHP: {i.PhpExecutable ?? "Not verified"}\nPublic URL: {i.PublicUrl ?? "Not resolved"}\nAdministrator: {i.AdministratorUrl ?? "Not resolved"}";
        ApplyConfiguration(i);
        RefreshRecoveryTarget();
        RefreshCounts();
    }
    private void ApplyConfiguration(JoomlaInstallation installation)
    {
        if (installation.Configuration?.Connection is not { } resolved) { ClearConnectionForm(); return; }
        _connection = resolved.Copy();
        _host.Text = resolved.Host;
        _port.Text = resolved.Port.ToString();
        _database.Text = resolved.Database;
        _username.Text = resolved.Username;
        _prefix.Text = resolved.Prefix;
        _databasePassword.Password = resolved.Password;
        _allowRemote.IsChecked = resolved.AllowRemote;
        _databaseSummary.Text = $"Configuration {installation.Configuration.Status}. Credentials remain hidden. Connection has not been tested.";
    }
    private async Task ResolveSelectedAsync()
    {
        await RunAsync("Resolving Joomla configuration", async ct =>
        {
            var installation = RequireInstallation();
            if (_controller.IsDemo)
            {
                ApplyConfiguration(installation);
                _installationDetail.Text = $"Synthetic configuration · {installation.Version}\n\n{string.Join("\n", installation.Configuration?.ReferenceChain ?? [])}\n\nThe isolated SQLite fixture remains the demo target.";
                Navigate("Database");
                return;
            }
            var roots = ReadScanOptions().Roots;
            var approved = new List<string>();
            ConfigurationResolution resolution = await Task.Run(() => _controller.Config.Resolve(installation.ConfigurationPath, roots, approved), ct);
            for (var step = 0; resolution.PendingApprovalPaths.Count > 0 && step < 8; step++)
            {
                var paths = string.Join("\n", resolution.PendingApprovalPaths);
                if (MessageBox.Show("This configuration references files outside the selected scope:\n\n" + paths +
                    "\n\nApprove reading these exact files for configuration resolution?", "Approve external configuration references",
                    MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes) break;
                approved.AddRange(resolution.PendingApprovalPaths);
                resolution = await Task.Run(() => _controller.Config.Resolve(installation.ConfigurationPath, roots, approved), ct);
            }
            installation.Configuration = resolution;
            installation.Status = resolution.Status;
            ApplyConfiguration(installation);
            _installationDetail.Text = $"JOOMLA {installation.Version}  ·  {resolution.Status}\n\n{installation.RootPath}\n\nReference chain:\n{string.Join("\n", resolution.ReferenceChain)}\n\nUnresolved fields: {string.Join(", ", resolution.UnresolvedFields)}\n{string.Join("\n", resolution.Findings.Select(f => f.Message))}";
            _installationGrid.Items.Refresh();
            AddEvidence("configuration", resolution.Status.ToString(), "Resolved selected Joomla configuration; secret values omitted.");
            Navigate("Database");
        });
    }
    private JoomlaInstallation RequireInstallation() => _selectedInstallation ?? throw new InvalidOperationException("Select a Joomla installation first.");
    private ConnectionSettings ReadConnection()
    {
        RequireInstallation();
        var result = _connection?.Copy() ?? new ConnectionSettings();
        if (!uint.TryParse(_port.Text, out var port) || port is < 1 or > 65535) throw new ArgumentException("Enter a valid port between 1 and 65535.");
        result.Host = _host.Text.Trim();
        result.Port = port;
        result.Database = _database.Text.Trim();
        result.Username = _username.Text.Trim();
        result.Prefix = _prefix.Text.Trim();
        result.Password = _databasePassword.Password;
        result.AllowRemote = _allowRemote.IsChecked == true;
        result.AuthenticationMethod = "Explicitly selected configuration or manual override";
        if (string.IsNullOrWhiteSpace(result.Database)) throw new ArgumentException("Enter the exact database name.");
        return result;
    }
    private async Task InspectDatabaseAsync()
    {
        await RunAsync("Inspecting selected database", async ct =>
        {
            var connection = ReadConnection();
            _connection = connection;
            _inspection = await _controller.Repository(connection).InspectAsync(connection, ct);
            ApplyInspection(_inspection);
            if (!_controller.IsDemo && _saveCredential.IsChecked == true && _inspection.Status is VerificationStatus.Accessible or VerificationStatus.Verified)
                _controller.Credentials.Save("database-" + connection.Id, connection.Username, connection.Password);
            AddEvidence("database", _inspection.Status.ToString(), $"Explicit metadata/account inspection; {_inspection.Tables.Count} tables and {_inspection.Accounts.Count} accounts observed.", new Dictionary<string, string> { ["database"] = connection.Database, ["table_prefix"] = connection.Prefix, ["action"] = "inspect_database" });
        });
    }
    private void ApplyInspection(DatabaseInspection inspection)
    {
        _databaseSummary.Text = $"{inspection.Status} · {inspection.EngineVersion}\nDatabase: {inspection.Database}  ·  Prefix: {inspection.Prefix}\n{string.Join("\n", inspection.Findings.Select(f => f.Message))}";
        _tableGrid.ItemsSource = inspection.Tables.Select(t => new { Name = t }).ToArray();
        FilterAccounts();
        _accountSummary.Text = $"{inspection.Accounts.Count} account(s) from the selected database. Group labels and administrator privileges are shown separately.";
        ConnectionBadge.Text = inspection.Status is VerificationStatus.Accessible or VerificationStatus.Verified ? "●  Database inspected" : "○  " + inspection.Status;
        RefreshCounts();
    }
    private void FilterAccounts()
    {
        var search = _accountSearch?.Text.Trim() ?? "";
        _accountGrid.ItemsSource = _inspection?.Accounts.Where(a => string.IsNullOrEmpty(search) ||
            $"{a.Id} {a.Username} {a.DisplayName} {a.Email} {a.Groups}".Contains(search, StringComparison.OrdinalIgnoreCase)).ToArray();
    }
    private async Task InspectSystemAsync()
    {
        await RunAsync("Inspecting local tools and services", async ct =>
        {
            if (_controller.IsDemo) { StatusText.Text = "Demo mode does not inspect live tools or services."; return; }
            _system = await _controller.System.InspectAsync(ReadScanOptions().Roots, ct);
            ShowSystemSnapshot(_system);
            AddEvidence("system", "Observed", "Explicit read-only inspection of scoped local tools and services.");
        });
    }
    private void ShowSystemSnapshot(SystemSnapshot snapshot)
    {
        _toolGrid.ItemsSource = snapshot.Tools;
        _serviceGrid.ItemsSource = snapshot.Services;
        _siteGrid.ItemsSource = snapshot.ApacheSites;
        _listenerText.Text = snapshot.ListeningPorts.Count == 0 ? "No listening ports observed in this snapshot." : "Observed listening ports: " + string.Join(", ", snapshot.ListeningPorts);
        _homeContext.Text = $"{snapshot.WindowsVersion}\n{snapshot.Tools.Count} tool observations · {snapshot.Services.Count} service observations · {snapshot.ListeningPorts.Count} listening ports";
    }
    private void OpenPhpMyAdmin()
    {
        var value = _controller.PhpMyAdminUrl();
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || (uri.Scheme != "https" && uri.Scheme != "http") || !string.IsNullOrEmpty(uri.UserInfo))
        {
            MessageBox.Show("A safe phpMyAdmin URL has not been resolved from scoped Apache configuration.", "Open phpMyAdmin", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        try { Process.Start(new ProcessStartInfo(uri.AbsoluteUri) { UseShellExecute = true }); }
        catch { StatusText.Text = "The URL could not be opened."; }
    }
    private void OpenSite(bool administrator)
    {
        if (_controller.IsDemo) { StatusText.Text = "Synthetic fixtures do not expose a real Joomla website."; return; }
        var i = _selectedInstallation;
        var value = administrator ? i?.AdministratorUrl : i?.PublicUrl;
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || (uri.Scheme != "https" && uri.Scheme != "http") || !string.IsNullOrEmpty(uri.UserInfo))
        {
            MessageBox.Show("A safe HTTP or HTTPS URL has not been resolved for this installation.", "Open Joomla", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        try { Process.Start(new ProcessStartInfo(uri.AbsoluteUri) { UseShellExecute = true }); }
        catch { StatusText.Text = "The URL could not be opened."; }
    }
    private async Task CheckAdministratorAsync()
    {
        await RunAsync("Checking selected administrator URL", async ct =>
        {
            if (_controller.IsDemo) { _installationDetail.Text += "\n\nSynthetic fixture: no live URL check is performed."; return; }
            var selected = RequireInstallation();
            var finding = await SiteReachability.CheckAsync(selected.AdministratorUrl, ct);
            _installationDetail.Text += $"\n\nURL CHECK · {finding.Status}\n{finding.Message}";
            AddEvidence("site-check", finding.Status.ToString(), finding.Message, new Dictionary<string,string> { ["action"] = "explicit_loopback_head_check" });
        });
    }
    private void AddEvidence(string kind, string status, string summary, IReadOnlyDictionary<string, string>? metadata = null)
    {
        try { _controller.Evidence.Add(new EvidenceEvent(DateTimeOffset.UtcNow, kind, _selectedInstallation?.Id ?? "", status, SafeMessage(summary), metadata)); }
        catch { StatusText.Text = "The operation finished, but local evidence could not be recorded."; }
    }
    private void RefreshCounts()
    {
        _installationCount.Text = _installations.Count.ToString();
        _configuredCount.Text = _installations.Count(i => i.Configuration?.Connection != null).ToString();
        _accountCount.Text = (_inspection?.Accounts.Count ?? 0).ToString();
        try { _evidenceCount.Text = _controller.Evidence.List().Count.ToString(); } catch { _evidenceCount.Text = "—"; }
    }
    private void RefreshEvidence()
    {
        try { _evidenceGrid.ItemsSource = _controller.Evidence.List(); } catch { _evidenceGrid.ItemsSource = null; }
    }

    private static TextBlock Text(string value, double size = 14, bool muted = false, FontWeight? weight = null)
    {
        var text = new TextBlock { Text = value, FontSize = size, FontWeight = weight ?? FontWeights.Normal, TextWrapping = TextWrapping.Wrap };
        text.SetResourceReference(TextBlock.ForegroundProperty, muted ? "MutedBrush" : "TextBrush");
        return text;
    }
    private static StackPanel Stack(params UIElement[] children)
    {
        var panel = new StackPanel();
        foreach (var child in children) panel.Children.Add(child);
        return panel;
    }
    private static StackPanel Row(params UIElement[] children)
    {
        var panel = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 12, 0, 0) };
        foreach (var child in children) panel.Children.Add(child);
        return panel;
    }
    private static Border Card(UIElement content, double padding = 22)
    {
        var card = new Border { CornerRadius = new CornerRadius(12), Padding = new Thickness(padding), Margin = new Thickness(0, 0, 0, 18), BorderThickness = new Thickness(1), Child = content };
        card.SetResourceReference(Border.BackgroundProperty, "CardBrush");
        card.SetResourceReference(Border.BorderBrushProperty, "BorderBrush");
        return card;
    }
    private static Grid Columns(params UIElement[] children)
    {
        var grid = new Grid();
        for (var index = 0; index < children.Length; index++)
        {
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            var holder = new Border { Child = children[index], Margin = new Thickness(0, 0, index == children.Length - 1 ? 0 : 16, 0) };
            Grid.SetColumn(holder, index); grid.Children.Add(holder);
        }
        return grid;
    }
    private static StackPanel Heading(string eyebrow, string title, string subtitle)
    {
        var e = Text(eyebrow.ToUpperInvariant(), 10, true, FontWeights.SemiBold);
        var h = Text(title, 29, false, FontWeights.SemiBold); h.Margin = new Thickness(0, 7, 0, 8);
        var s = Text(subtitle, 14, true); s.Margin = new Thickness(0, 0, 0, 24);
        return Stack(e, h, s);
    }
    private static TextBox Input(string name, string value = "", bool multiline = false, double height = double.NaN)
    {
        var box = new TextBox { Text = value, AcceptsReturn = multiline, TextWrapping = multiline ? TextWrapping.Wrap : TextWrapping.NoWrap, Height = height, VerticalScrollBarVisibility = multiline ? ScrollBarVisibility.Auto : ScrollBarVisibility.Disabled, VerticalContentAlignment = multiline ? VerticalAlignment.Top : VerticalAlignment.Center };
        AutomationProperties.SetName(box, name);
        return box;
    }
    private static TextBox Readout(string name, double height = 140)
    {
        var box = Input(name, "", true, height); box.IsReadOnly = true; box.FontFamily = new FontFamily("Cascadia Code, Consolas"); box.FontSize = 12;
        return box;
    }
    private static PasswordBox Secret(string name)
    {
        var box = new PasswordBox(); AutomationProperties.SetName(box, name); return box;
    }
    private static StackPanel Field(string title, Control control, string? hint = null)
    {
        var label = Text(title, 12, false, FontWeights.SemiBold); label.Margin = new Thickness(0, 0, 0, 7);
        var panel = Stack(label, control); panel.Margin = new Thickness(0, 0, 0, 16);
        if (hint != null) { var note = Text(hint, 11, true); note.Margin = new Thickness(0, 6, 0, 0); panel.Children.Add(note); }
        return panel;
    }
    private Button Action(string title, Func<Task> handler, bool primary = false, bool operation = false)
    {
        var button = new Button { Content = title };
        if (primary) button.Style = (Style)FindResource("PrimaryButton");
        button.Click += async (_, _) => { try { await handler(); } catch (Exception ex) { MessageBox.Show(SafeMessage(SecretSafety.Error(ex)), title, MessageBoxButton.OK, MessageBoxImage.Warning); } };
        AutomationProperties.SetName(button, title);
        if (operation) _operationButtons.Add(button);
        return button;
    }
    private Button Action(string title, Action handler, bool primary = false) => Action(title, () => { handler(); return Task.CompletedTask; }, primary);
    private static DataGrid Table(string name, double height, params (string Header, string Path, double Width)[] columns)
    {
        var table = new DataGrid { Height = height, Margin = new Thickness(0, 14, 0, 0) };
        AutomationProperties.SetName(table, name);
        foreach (var column in columns)
        {
            var style = new Style(typeof(TextBlock));
            style.Setters.Add(new Setter(TextBlock.TextTrimmingProperty, TextTrimming.CharacterEllipsis));
            style.Setters.Add(new Setter(TextBlock.TextWrappingProperty, TextWrapping.NoWrap));
            style.Setters.Add(new Setter(TextBlock.ToolTipProperty, new Binding(column.Path)));
            table.Columns.Add(new DataGridTextColumn { Header = column.Header, Binding = new Binding(column.Path), ElementStyle = style, Width = new DataGridLength(column.Width, DataGridLengthUnitType.Star) });
        }
        return table;
    }
    private void Register(string name, FrameworkElement page)
    {
        _pages[name] = page; page.Visibility = Visibility.Collapsed; PageHost.Children.Add(page);
    }
}
