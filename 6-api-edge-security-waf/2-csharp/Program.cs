using System.Text;
using WafGateway;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

var backendUrl = Environment.GetEnvironmentVariable("BACKEND_URL") ?? "http://localhost:4000";
var httpClient = new HttpClient();

// The WAF middleware is the API edge — registered before any endpoint so every
// request is filtered first. Clean traffic continues to the proxy below.
app.UseMiddleware<WafMiddleware>();

app.MapGet("/healthz", () => Results.Ok(new { status = "ok" }));

app.MapPost("/api/echo", async (HttpRequest request) =>
{
    // Forward the vetted payload to the backend and relay its response.
    using var reader = new StreamReader(request.Body, Encoding.UTF8);
    var raw = await reader.ReadToEndAsync();
    var content = new StringContent(raw, Encoding.UTF8, "application/json");
    var resp = await httpClient.PostAsync($"{backendUrl}/echo", content);
    var echoJson = await resp.Content.ReadAsStringAsync();
    using var doc = System.Text.Json.JsonDocument.Parse(echoJson);
    return Results.Ok(new { status = "allowed", echo = doc.RootElement.Clone() });
});

var port = Environment.GetEnvironmentVariable("PORT") ?? "3000";
app.Run($"http://0.0.0.0:{port}");
