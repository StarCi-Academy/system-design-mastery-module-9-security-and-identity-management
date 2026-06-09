// Fine-grained authorization demo (ASP.NET Core minimal API).
// The app externalizes every decision to OPA: a thin authz layer builds the OPA
// input from request headers + the resource, calls OPA's decision API, and maps
// allow/deny to HTTP 200/403. No policy logic lives in the app.

using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);
// Register OpaService as a singleton — it holds only an HttpClient and a URL string.
builder.Services.AddSingleton<OpaService>();
var app = builder.Build();

// Liveness probe — not gated by any policy.
app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

// GET /documents/{id}/{action} — the authz middleware (policy enforcement point).
app.MapGet("/documents/{id}/{action}", async (string id, string action, HttpRequest req, OpaService opa) =>
{
    // Reject unknown resources before calling OPA to keep decisions scoped.
    if (!ResourceCatalog.Resources.TryGetValue(id, out var resource))
    {
        return Results.NotFound(new { status = "error", message = $"Unknown resource {id}" });
    }

    // Parse identity from headers; a real app would read a verified JWT instead.
    var rolesHeader = req.Headers["x-user-roles"].ToString();
    var clearanceHeader = req.Headers["x-user-clearance"].ToString();
    var user = new UserContext(
        req.Headers["x-user-id"].ToString(),
        // Empty roles header → empty array; avoids a null/empty-string edge case in Rego.
        string.IsNullOrWhiteSpace(rolesHeader)
            ? Array.Empty<string>()
            : rolesHeader.Split(',', StringSplitOptions.TrimEntries),
        req.Headers["x-user-department"].ToString(),
        // Coerce clearance to int — the Rego >= predicate compares numbers.
        int.TryParse(clearanceHeader, out var c) ? c : 0);

    // Delegate the allow/deny decision entirely to OPA.
    var (allow, reason) = await opa.EvaluateAsync(new OpaInput(user, action, resource));
    if (!allow)
    {
        // OPA denied — surface the policy reason so the caller knows which predicate failed.
        return Results.Json(new { status = "deny", allowed = false, reason }, statusCode: 403);
    }

    // OPA allowed — echo back the decision for observability.
    return Results.Ok(new { status = "allow", allowed = true, reason, resource = resource.Id, action });
});

// Bind to all interfaces so the Docker port mapping is reachable from outside the container.
app.Run("http://0.0.0.0:" + (Environment.GetEnvironmentVariable("PORT") ?? "3000"));

// ---- Types ----

/// <summary>
/// Identity attributes extracted from request headers for the OPA input document.
/// </summary>
/// <param name="Id">Unique user identifier (e.g. "alice").</param>
/// <param name="Roles">Role names carried by the user (e.g. ["admin"]).</param>
/// <param name="Department">Organisational department the user belongs to.</param>
/// <param name="Clearance">Numeric security clearance — compared against resource sensitivity.</param>
public record UserContext(string Id, string[] Roles, string Department, int Clearance);

/// <summary>
/// A protected resource stored in the in-memory catalog and included in the OPA input.
/// </summary>
/// <param name="Id">Unique resource identifier (e.g. "report-finance").</param>
/// <param name="Type">Resource category (e.g. "report") — informational only.</param>
/// <param name="Owner">User-id of the principal who owns the resource (used by ReBAC).</param>
/// <param name="Department">Organisational department the resource belongs to (used by ABAC).</param>
/// <param name="Sensitivity">Sensitivity level — user clearance must be &gt;= this for ABAC read.</param>
public record Resource(string Id, string Type, string Owner, string Department, int Sensitivity);

/// <summary>
/// The exact JSON document POSTed to OPA as the <c>"input"</c> field.
/// </summary>
/// <param name="User">Identity context for the requesting principal.</param>
/// <param name="Action">Action being attempted: read | write | delete.</param>
/// <param name="Resource">Resource being acted upon.</param>
public record OpaInput(UserContext User, string Action, Resource Resource);

/// <summary>
/// Static in-memory resource catalog, identical to the other language tracks.
/// Keyed by resource id for O(1) lookup in the request handler.
/// </summary>
public static class ResourceCatalog
{
    /// <summary>All known resources, seeded at startup.</summary>
    public static readonly Dictionary<string, Resource> Resources = new()
    {
        // finance report — owned by alice, sensitivity 2 (medium)
        ["report-finance"] = new Resource("report-finance", "report", "alice", "finance", 2),
        // engineering report — owned by bob, sensitivity 3 (high)
        ["report-eng"] = new Resource("report-eng", "report", "bob", "engineering", 3),
    };
}

/// <summary>
/// OpaService asks OPA for an authorization decision over HTTP.
/// The app holds no policy logic — every allow/deny is delegated to OPA's decision API.
/// </summary>
public class OpaService
{
    /// <summary>HTTP client reused across requests (not disposed per-call).</summary>
    private readonly HttpClient _http = new();

    /// <summary>Full URL to the OPA data path that maps to package app.authz.</summary>
    private readonly string _url;

    /// <summary>
    /// Serializer options that emit camelCase JSON so Rego can read <c>input.user.id</c>
    /// rather than the default C# PascalCase <c>input.User.Id</c>.
    /// </summary>
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    /// <summary>
    /// Construct OpaService, resolving the OPA base URL from the environment.
    /// </summary>
    /// <param name="config">ASP.NET configuration (unused; URL comes from env var for parity with other tracks).</param>
    public OpaService(IConfiguration config)
    {
        // Read OPA_BASE_URL from the environment; fall back to the docker-network hostname.
        var baseUrl = Environment.GetEnvironmentVariable("OPA_BASE_URL") ?? "http://opa:8181";
        // Append the data path: /v1/data/app/authz mirrors the Rego package name.
        _url = baseUrl + "/v1/data/app/authz";
    }

    /// <summary>
    /// Evaluate an OPA input document and return the authorization decision.
    /// </summary>
    /// <param name="input">The context document (user + action + resource) for this request.</param>
    /// <returns>A tuple of (Allow, Reason) from OPA's decision document.</returns>
    public async Task<(bool Allow, string Reason)> EvaluateAsync(OpaInput input)
    {
        // Wrap in { "input": ... } — OPA binds the value to the `input` document in Rego.
        // CamelCase policy ensures C# PascalCase properties serialize to lowercase keys.
        var payload = JsonSerializer.Serialize(new { input }, JsonOpts);
        var content = new StringContent(payload, System.Text.Encoding.UTF8, "application/json");
        var response = await _http.PostAsync(_url, content);
        var body = await response.Content.ReadAsStringAsync();
        // Parse the OPA envelope and extract the result object.
        using var doc = JsonDocument.Parse(body);
        var result = doc.RootElement.GetProperty("result");
        // Return only the two fields the handler needs; leave OPA internals behind.
        return (result.GetProperty("allow").GetBoolean(), result.GetProperty("reason").GetString() ?? "");
    }
}
