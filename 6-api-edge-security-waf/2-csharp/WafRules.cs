using System.Text.Json;
using System.Text.RegularExpressions;

namespace WafGateway;

// WAF rule set — portable across all four language tracks. Each rule has a stable
// id ("sql_injection", "xss", "ssrf") and a regex flagging one OWASP risk class,
// mirroring the TypeScript / Java / Go tracks so the contract is identical.
public static class WafRules
{
    private record Rule(string Id, Regex Pattern);

    private static readonly Rule[] Rules =
    {
        new("sql_injection",
            new Regex(@"('\s*or\s*'?\d|union\s+select|;\s*drop\s+table|--\s|/\*|\bor\s+1\s*=\s*1\b)",
                RegexOptions.IgnoreCase | RegexOptions.Compiled)),
        new("xss",
            new Regex(@"(<\s*script|<\s*img[^>]*\son\w+\s*=|javascript:|on(error|load|click)\s*=)",
                RegexOptions.IgnoreCase | RegexOptions.Compiled)),
        new("ssrf",
            new Regex(@"(169\.254\.169\.254|127\.0\.0\.1|localhost|0\.0\.0\.0|metadata\.google|file://|169\.254\.|\[::1\])",
                RegexOptions.IgnoreCase | RegexOptions.Compiled)),
    };

    // Return the first rule id a single string trips, or null.
    public static string? InspectValue(string value)
    {
        foreach (var rule in Rules)
        {
            if (rule.Pattern.IsMatch(value))
            {
                return rule.Id;
            }
        }
        return null;
    }

    // Walk a parsed JSON element and inspect every leaf string value.
    public static string? InspectPayload(JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.String:
                return InspectValue(element.GetString() ?? string.Empty);
            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray())
                {
                    var hit = InspectPayload(item);
                    if (hit != null) return hit;
                }
                return null;
            case JsonValueKind.Object:
                foreach (var prop in element.EnumerateObject())
                {
                    var hit = InspectPayload(prop.Value);
                    if (hit != null) return hit;
                }
                return null;
            default:
                return null;
        }
    }
}
