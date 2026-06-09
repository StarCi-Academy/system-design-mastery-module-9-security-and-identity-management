using AuditLogApi;
using Npgsql;

var builder = WebApplication.CreateBuilder(args);

string Env(string key, string fallback) =>
    Environment.GetEnvironmentVariable(key) is { Length: > 0 } v ? v : fallback;

var connString = new NpgsqlConnectionStringBuilder
{
    Host = Env("DB_HOST", "localhost"),
    Port = int.Parse(Env("DB_PORT", "5432")),
    Username = Env("DB_USER", "admin"),
    Password = Env("DB_PASSWORD", "123456"),
    Database = Env("DB_NAME", "auditdb"),
}.ConnectionString;

var dataSource = NpgsqlDataSource.Create(connString);
builder.Services.AddSingleton(dataSource);
builder.Services.AddSingleton<AuditRepository>();

builder.WebHost.UseUrls($"http://0.0.0.0:{Env("PORT", "3000")}");

var app = builder.Build();

var repo = app.Services.GetRequiredService<AuditRepository>();
// Retry until Postgres accepts connections, then ensure the schema exists.
for (var i = 0; i < 30; i++)
{
    try
    {
        await repo.InitSchemaAsync();
        break;
    }
    catch (Exception) when (i < 29)
    {
        await Task.Delay(1000);
    }
}

// POST /events — append one event, returning index + the two hashes (HTTP 201).
app.MapPost("/events", async (AppendDto? dto, AuditRepository r) =>
{
    var actor = dto?.actor ?? "unknown";
    var action = dto?.action ?? "unknown";
    var target = dto?.target ?? "unknown";
    var result = await r.AppendAsync(actor, action, target);
    return Results.Json(result, statusCode: 201);
});

// GET /verify — recompute the chain and report OK or the first broken index.
app.MapGet("/verify", async (AuditRepository r) => Results.Json(await r.VerifyAsync()));

app.Run();

public record AppendDto(string? actor, string? action, string? target);
