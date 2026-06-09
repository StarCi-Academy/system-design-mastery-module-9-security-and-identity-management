using Microsoft.EntityFrameworkCore;
using SecretApi;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSingleton<VaultService>();

// Await the runtime Vault fetch BEFORE materializing the DbContext options.
var vault = new VaultService(LoggerFactory.Create(b => b.AddConsole())
    .CreateLogger<VaultService>());
var dbPassword = await vault.FetchDatabasePasswordAsync();

var host = Environment.GetEnvironmentVariable("DB_HOST") ?? "localhost";
var port = Environment.GetEnvironmentVariable("DB_PORT") ?? "5432";
var user = Environment.GetEnvironmentVariable("DB_USER") ?? "admin";
var name = Environment.GetEnvironmentVariable("DB_NAME") ?? "userdb";
var connString = $"Host={host};Port={port};Username={user};Password={dbPassword};Database={name}";

builder.Services.AddDbContext<AppDbContext>(opt => opt.UseNpgsql(connString));

var app = builder.Build();

// Seed demo data once so GET /users returns rows immediately.
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.EnsureCreated();
    if (!db.Users.Any())
    {
        db.Users.AddRange(new User { Name = "Admin StarCi" }, new User { Name = "Học viên VIP" });
        db.SaveChanges();
    }
}

// GET /users — proves the Vault-sourced password opened a real DB connection.
app.MapGet("/users", async (AppDbContext db) =>
{
    var data = await db.Users
        .Select(u => new { id = u.Id, name = u.Name })
        .ToListAsync();
    return Results.Ok(new { status = "success", data });
});

var listenPort = Environment.GetEnvironmentVariable("PORT") ?? "3000";
app.Run($"http://0.0.0.0:{listenPort}");
