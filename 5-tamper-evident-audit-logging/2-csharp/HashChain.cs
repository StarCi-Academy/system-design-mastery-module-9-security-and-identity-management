using System.Security.Cryptography;
using System.Text;

namespace AuditLogApi;

// Portable hash-chain core. The canonical serialization (fixed field order joined
// with "|", then sha256 hex) MUST be byte-identical across all four languages.
public static class HashChain
{
    // The 64-zero genesis prevHash anchors the first entry — there is no row before index 0.
    public const string GenesisPrevHash = "0000000000000000000000000000000000000000000000000000000000000000";

    public static string ComputeEntryHash(int index, string prevHash, string actor,
        string action, string target, long timestamp)
    {
        var payload = $"{index}|{prevHash}|{actor}|{action}|{target}|{timestamp}";
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(payload));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
