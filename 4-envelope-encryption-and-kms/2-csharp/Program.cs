using EnvelopeApi;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

string Env(string k, string def) => Environment.GetEnvironmentVariable(k) is { Length: > 0 } v ? v : def;

var connString =
    $"Host={Env("DB_HOST", "localhost")};Port={Env("DB_PORT", "5432")};" +
    $"Database={Env("DB_NAME", "vaultdb")};Username={Env("DB_USER", "admin")};Password={Env("DB_PASSWORD", "123456")}";

builder.Services.AddDbContext<AppDbContext>(opt => opt.UseNpgsql(connString));
builder.Services.AddSingleton(new EnvelopeService(
    Env("VAULT_ADDR", "http://localhost:8200"),
    Env("VAULT_TOKEN", "root"),
    Env("KEK_NAME", "app-kek")));

var app = builder.Build();

// Ensure schema + KEK exist before serving traffic.
using (var scope = app.Services.CreateScope())
{
    await scope.ServiceProvider.GetRequiredService<AppDbContext>().Database.EnsureCreatedAsync();
    await scope.ServiceProvider.GetRequiredService<EnvelopeService>().EnsureKekAsync();
}

// POST /records — encrypt and store ciphertext + wrapped DEK.
app.MapPost("/records", async (PlaintextDto dto, AppDbContext db, EnvelopeService svc) =>
{
    var env = await svc.EncryptAsync(dto.Plaintext);
    var rec = new SecureRecord { WrappedDek = env.WrappedDek, Iv = env.Iv, Ciphertext = env.Ciphertext };
    db.SecureRecords.Add(rec);
    await db.SaveChangesAsync();
    return Results.Created($"/records/{rec.Id}", new { id = rec.Id, status = "encrypted" });
});

// GET /records/{id} — unwrap the DEK, decrypt, return plaintext (422 if KEK shredded).
app.MapGet("/records/{id:int}", async (int id, AppDbContext db, EnvelopeService svc) =>
{
    var rec = await db.SecureRecords.FindAsync(id);
    if (rec is null) return Results.NotFound(new { status = "not_found" });
    try
    {
        var plaintext = await svc.DecryptAsync(rec.WrappedDek, rec.Iv, rec.Ciphertext);
        return Results.Ok(new { id = rec.Id, plaintext });
    }
    catch
    {
        return Results.Json(new { status = "unrecoverable" }, statusCode: 422);
    }
});

// POST /kek/rotate — bump the KEK version; old wrapped DEKs stay valid.
app.MapPost("/kek/rotate", async (EnvelopeService svc) =>
{
    var version = await svc.RotateKekAsync();
    return Results.Ok(new { status = "rotated", version });
});

// POST /kek/shred — crypto-shredding: delete the KEK; all records become unrecoverable.
app.MapPost("/kek/shred", async (EnvelopeService svc) =>
{
    await svc.ShredKekAsync();
    return Results.Ok(new { status = "shredded" });
});

app.Run($"http://0.0.0.0:{Env("PORT", "3000")}");

public record PlaintextDto(string Plaintext);
