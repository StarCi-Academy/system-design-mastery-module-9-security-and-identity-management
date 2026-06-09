// Identity & Keycloak lab — ASP.NET Core minimal API.
// AddJwtBearer with Authority pointed at the realm validates JWTs OFFLINE against
// Keycloak's auto-discovered JWKS. Public + confidential client demo and a protected
// /api/orders resource. English-only comments per repo convention.

using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

var keycloakBaseUrl = Environment.GetEnvironmentVariable("KEYCLOAK_BASE_URL") ?? "http://keycloak:8080";
var realm = Environment.GetEnvironmentVariable("KEYCLOAK_REALM") ?? "starci-realm";
var publicClientId = Environment.GetEnvironmentVariable("KEYCLOAK_PUBLIC_CLIENT_ID") ?? "csharp-app";
var privateClientId = Environment.GetEnvironmentVariable("KEYCLOAK_PRIVATE_CLIENT_ID") ?? "csharp-private-app";
var privateClientSecret = Environment.GetEnvironmentVariable("KEYCLOAK_PRIVATE_CLIENT_SECRET") ?? "super-secret-key";
var defaultUsername = Environment.GetEnvironmentVariable("KEYCLOAK_DEFAULT_USERNAME") ?? "student";
var defaultPassword = Environment.GetEnvironmentVariable("KEYCLOAK_DEFAULT_PASSWORD") ?? "student123";
var redirectUri = Environment.GetEnvironmentVariable("KEYCLOAK_REDIRECT_URI") ?? "http://localhost:3000/auth/callback";
var port = Environment.GetEnvironmentVariable("PORT") ?? "3000";

var realmBase = $"{keycloakBaseUrl}/realms/{realm}";
var tokenEndpoint = $"{realmBase}/protocol/openid-connect/token";
var authorizeEndpoint = $"{realmBase}/protocol/openid-connect/auth";

builder.WebHost.UseUrls($"http://0.0.0.0:{port}");

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        // Authority points at the realm; ASP.NET auto-discovers JWKS from .well-known.
        options.Authority = realmBase;
        // Dev mode runs Keycloak over HTTP; require HTTPS in production.
        options.RequireHttpsMetadata = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            // Verify the RS256 signature with Keycloak's published public key.
            ValidateIssuerSigningKey = true,
            ValidateIssuer = true,
            ValidIssuer = realmBase,
            // Keycloak does not set "aud" to the API by default; skip audience check here.
            ValidateAudience = false,
        };
    });

builder.Services.AddAuthorization();
builder.Services.AddHttpClient();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

var httpFactory = app.Services.GetRequiredService<IHttpClientFactory>();

// POST a form-urlencoded body to Keycloak's /token endpoint (JSON is rejected with 415).
async Task<IResult> FetchToken(Dictionary<string, string> form)
{
    var client = httpFactory.CreateClient();
    var resp = await client.PostAsync(tokenEndpoint, new FormUrlEncodedContent(form));
    var body = await resp.Content.ReadAsStringAsync();
    if (!resp.IsSuccessStatusCode)
    {
        return Results.Json(new { statusCode = (int)resp.StatusCode, message = body }, statusCode: 400);
    }
    return Results.Content(body, "application/json");
}

string Pick(Dictionary<string, string>? body, string key, string def)
    => body != null && body.TryGetValue(key, out var v) && !string.IsNullOrEmpty(v) ? v : def;

// Health probe + endpoint listing (public).
app.MapGet("/", () => Results.Json(new
{
    status = "ok",
    message = "Identity Keycloak ASP.NET Core demo is running.",
    endpoints = new
    {
        loginPublic = "POST /auth/login/public",
        loginPrivate = "POST /auth/login/private",
        authorizeUrl = "GET /auth/authorize/url",
        authCallback = "GET /auth/callback?code=...",
        protectedOrders = "GET /api/orders (requires Bearer token)",
    },
})).AllowAnonymous();

// Password grant via the public client (no secret).
app.MapPost("/auth/login/public", async (Dictionary<string, string>? body) =>
{
    var form = new Dictionary<string, string>
    {
        ["client_id"] = publicClientId,
        ["grant_type"] = "password",
        ["username"] = Pick(body, "username", defaultUsername),
        ["password"] = Pick(body, "password", defaultPassword),
    };
    return await FetchToken(form);
}).AllowAnonymous();

// Password grant via the confidential client (with client_secret).
app.MapPost("/auth/login/private", async (Dictionary<string, string>? body) =>
{
    var form = new Dictionary<string, string>
    {
        ["client_id"] = privateClientId,
        ["client_secret"] = privateClientSecret,
        ["grant_type"] = "password",
        ["username"] = Pick(body, "username", defaultUsername),
        ["password"] = Pick(body, "password", defaultPassword),
    };
    return await FetchToken(form);
}).AllowAnonymous();

app.MapGet("/auth/authorize/url", () =>
{
    var url = $"{authorizeEndpoint}?client_id={publicClientId}&response_type=code"
        + $"&scope=openid+profile+email&redirect_uri={Uri.EscapeDataString(redirectUri)}&state={Guid.NewGuid()}";
    return Results.Json(new { authorizeUrl = url, note = "Open authorizeUrl in browser, then copy `code` from callback query params." });
}).AllowAnonymous();

app.MapGet("/auth/callback", async (string? code) =>
{
    var form = new Dictionary<string, string>
    {
        ["client_id"] = publicClientId,
        ["grant_type"] = "authorization_code",
        ["code"] = code ?? "",
        ["redirect_uri"] = redirectUri,
    };
    return await FetchToken(form);
}).AllowAnonymous();

// Protected resource — gated by the JWT bearer middleware.
app.MapGet("/api/orders", (ClaimsPrincipal user) =>
{
    var username = user.FindFirstValue("preferred_username")
        ?? user.FindFirstValue(ClaimTypes.Email)
        ?? "user";
    return Results.Json(new
    {
        status = "success",
        message = $"Welcome {username}. Here are your orders",
        data = new[]
        {
            new { id = 1, total = 500 },
            new { id = 2, total = 1000 },
        },
    });
}).RequireAuthorization();

app.Run();
