using System.Text;
using System.Text.Json;

namespace WafGateway;

// WAF middleware — the API-edge filter. It runs before the endpoint handlers,
// inspecting query string, headers, and JSON body. Malicious payloads are
// short-circuited with 403; clean requests flow on to the backend proxy.
public class WafMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<WafMiddleware> _logger;

    public WafMiddleware(RequestDelegate next, ILogger<WafMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // 1. Inspect every query-string value.
        foreach (var pair in context.Request.Query)
        {
            var hit = WafRules.InspectValue(pair.Value.ToString());
            if (hit != null) { await BlockAsync(context, hit); return; }
        }

        // 2. Inspect user-controlled headers.
        var headerHit =
            WafRules.InspectValue(context.Request.Headers["X-Forwarded-For"].ToString())
            ?? WafRules.InspectValue(context.Request.Headers["Referer"].ToString());
        if (headerHit != null) { await BlockAsync(context, headerHit); return; }

        // 3. Inspect the JSON body recursively, then rewind it for the handler.
        context.Request.EnableBuffering();
        if (context.Request.ContentLength is > 0)
        {
            using var reader = new StreamReader(
                context.Request.Body, Encoding.UTF8, leaveOpen: true);
            var raw = await reader.ReadToEndAsync();
            context.Request.Body.Position = 0;
            if (!string.IsNullOrEmpty(raw))
            {
                try
                {
                    using var doc = JsonDocument.Parse(raw);
                    var bodyHit = WafRules.InspectPayload(doc.RootElement);
                    if (bodyHit != null) { await BlockAsync(context, bodyHit); return; }
                }
                catch (JsonException) { /* non-JSON body: nothing to inspect */ }
            }
        }

        await _next(context);
    }

    private async Task BlockAsync(HttpContext context, string rule)
    {
        _logger.LogWarning("BLOCKED {Method} {Path} rule={Rule}",
            context.Request.Method, context.Request.Path, rule);
        // Uniform 403 contract — never echo the offending payload back.
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        await context.Response.WriteAsJsonAsync(new { status = "blocked", rule });
    }
}
