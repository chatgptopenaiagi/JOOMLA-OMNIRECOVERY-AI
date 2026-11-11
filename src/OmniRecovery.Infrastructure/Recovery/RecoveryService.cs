using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using OmniRecovery.Core;
using OmniRecovery.Infrastructure.Database;

namespace OmniRecovery.Infrastructure.Recovery;

/// <summary>Application authorization boundary. Catalog/inspection results never authorize mutation.</summary>
public sealed class RecoveryService(IAccountRepository repository, IPasswordHasher? hasher = null, TimeProvider? clock = null)
{
    private readonly IPasswordHasher hasher = hasher ?? new BCryptPasswordHasher();
    private readonly TimeProvider clock = clock ?? TimeProvider.System;
    private readonly ConcurrentDictionary<string, RecoveryPreview> approvals = new(StringComparer.Ordinal);
    public static void RequireSupportedVersion(string version)
    {
        if (string.IsNullOrWhiteSpace(version) || !Regex.IsMatch(version, @"^[45]\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$", RegexOptions.CultureInvariant))
            throw new NotSupportedException("Direct fallback is limited to explicitly identified Joomla 4.x or 5.x releases. Unknown and other versions are unsupported.");
    }
    public static void RequireTargetBinding(JoomlaInstallation installation, ConnectionSettings selected)
    {
        var configured = installation.Configuration?.Connection;
        if (configured is null) throw new InvalidOperationException("Recovery requires a resolved selected Joomla configuration. Manual or unresolved targets support inspection only.");
        static string Engine(string value) => value.ToLowerInvariant() is "mysql" or "mysqli" or "mariadb" ? "mysql" : value.ToLowerInvariant();
        static string Host(string value) => System.Net.IPAddress.TryParse(value, out var address) ? address.ToString() : value.ToLowerInvariant();
        var same = Engine(configured.Engine) == Engine(selected.Engine)
            && Host(configured.Host) == Host(selected.Host) && configured.Port == selected.Port
            && string.Equals(configured.Database, selected.Database, StringComparison.Ordinal)
            && string.Equals(configured.Prefix, selected.Prefix, StringComparison.Ordinal);
        if (Engine(selected.Engine) == "sqlite")
            same &= !string.IsNullOrWhiteSpace(configured.SqlitePath) && !string.IsNullOrWhiteSpace(selected.SqlitePath)
                && string.Equals(Path.GetFullPath(configured.SqlitePath), Path.GetFullPath(selected.SqlitePath), StringComparison.OrdinalIgnoreCase);
        if (!same) throw new InvalidOperationException("Recovery target differs from the selected Joomla configuration. Resolve the matching installation before recovery; only credential overrides are allowed. Manual target overrides remain inspection-only.");
    }
    public async Task<RecoveryPreview> PreviewAsync(JoomlaInstallation installation, ConnectionSettings connection, long accountId, bool directFallbackOptIn,
        CancellationToken ct = default, string? fallbackReason = null)
    {
        if (!directFallbackOptIn) throw new InvalidOperationException("Explicit direct-fallback opt-in is required after reviewing supported Joomla recovery mechanisms.");
        if (string.IsNullOrWhiteSpace(fallbackReason) || fallbackReason.Trim().Length is < 12 or > 500) throw new ArgumentException("Record a 12–500 character reason why supported recovery mechanisms are unavailable.");
        RequireSupportedVersion(installation.Version);
        RequireTargetBinding(installation, connection);
        if (repository is not IRecoveryPreviewRepository previewRepository) throw new NotSupportedException("Repository does not implement guarded preview issuance.");
        foreach (var id in approvals.Where(p => p.Value.ExpiresAt <= clock.GetUtcNow()).Select(p => p.Key)) approvals.TryRemove(id, out _);
        var preview = await previewRepository.CreateRecoveryPreviewAsync(installation, connection, accountId, ct);
        approvals[preview.PreviewId] = preview;
        return preview;
    }
    public async Task<RecoveryOutcome> ExecuteAsync(ConnectionSettings connection, RecoveryPreview preview, string confirmation, string newPassword,
        bool directFallbackOptIn, CancellationToken ct = default)
    {
        if (!directFallbackOptIn) throw new InvalidOperationException("Direct-fallback opt-in is required.");
        RequireSupportedVersion(preview.JoomlaVersion);
        if (!string.Equals(confirmation, preview.ConfirmationText, StringComparison.Ordinal)) throw new InvalidOperationException("Confirmation must exactly match the selected username confirmation text.");
        if (!approvals.TryGetValue(preview.PreviewId, out var issued) || issued != preview || preview.ExpiresAt <= clock.GetUtcNow()) throw new InvalidOperationException("A current unchanged preview from this recovery session is required.");
        BCryptPasswordHasher.ValidatePassword(newPassword);
        ct.ThrowIfCancellationRequested();
        var hash = hasher.Hash(newPassword);
        if (!approvals.TryRemove(preview.PreviewId, out _)) throw new InvalidOperationException("Preview was already consumed.");
        return await repository.ResetPasswordAsync(connection, preview, hash, ct);
    }
}
