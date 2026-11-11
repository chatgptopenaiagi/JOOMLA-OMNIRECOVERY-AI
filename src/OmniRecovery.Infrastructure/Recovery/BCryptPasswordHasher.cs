using System.Security.Cryptography;
using System.Text;
using OmniRecovery.Core;

namespace OmniRecovery.Infrastructure.Recovery;

public sealed class BCryptPasswordHasher : IPasswordHasher
{
    public string Hash(string password)
    {
        ValidatePassword(password);
        // PHP/Joomla HASH_BCRYPT uses the 2y revision; BCrypt.Net accepts it for verification.
        var hash = BCrypt.Net.BCrypt.HashPassword(password, workFactor: 12);
        return "$2y$" + hash[4..];
    }
    public bool Verify(string password, string hash)
    {
        try { ValidatePassword(password); return BCrypt.Net.BCrypt.Verify(password, hash); }
        catch (ArgumentException) { return false; }
        catch (BCrypt.Net.SaltParseException) { return false; }
    }
    public string GeneratePassword() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(18)); // Exactly 24 ASCII characters / 144 random bits.
    public static void ValidatePassword(string password)
    {
        if (string.IsNullOrEmpty(password) || password.Length < 12 || password.IndexOf('\0') >= 0 || password.Any(char.IsControl)) throw new ArgumentException("Use at least 12 characters without null/control characters.");
        // Reject malformed surrogate sequences and byte truncation instead of silently hashing a prefix.
        var encoding = new UTF8Encoding(false, true);
        try { if (encoding.GetByteCount(password) > 72) throw new ArgumentException("bcrypt permits at most 72 UTF-8 bytes; choose a shorter password."); }
        catch (EncoderFallbackException) { throw new ArgumentException("Password contains invalid Unicode."); }
    }
}
