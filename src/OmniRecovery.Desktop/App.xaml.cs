using System.Windows;
using OmniRecovery.Infrastructure.Services;

namespace OmniRecovery.Desktop;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        bool smoke = e.Args.Contains("--smoke-test", StringComparer.OrdinalIgnoreCase);
        bool demo = smoke || e.Args.Contains("--demo", StringComparer.OrdinalIgnoreCase);
        DispatcherUnhandledException += (_, args) =>
        {
            MessageBox.Show("The application could not complete this operation. No automatic retry was attempted.",
                "OmniRecovery", MessageBoxButton.OK, MessageBoxImage.Error);
            args.Handled = true;
        };
        var window = new MainWindow(new ApplicationController(demo), smoke);
        MainWindow = window;
        window.Show();
    }
}
