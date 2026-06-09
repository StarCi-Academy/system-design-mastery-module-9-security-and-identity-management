using System.Security.Cryptography.X509Certificates;

// service-a — the mTLS client. It exposes a plain HTTP surface and calls service-b
// over mutual TLS. /call presents a valid client cert (authenticated 200);
// /call-no-cert presents none, so service-b rejects the handshake and we return 502.
var certsDir = Environment.GetEnvironmentVariable("CERTS_DIR") ?? "/certs";
var port = Environment.GetEnvironmentVariable("PORT") ?? "3000";
var targetHost = Environment.GetEnvironmentVariable("SERVICE_B_HOST") ?? "service-b";
var targetPort = Environment.GetEnvironmentVariable("SERVICE_B_PORT") ?? "8443";
var target = $"https://{targetHost}:{targetPort}/secure";

var caCert = new X509Certificate2($"{certsDir}/ca.crt");
var clientCert = X509Certificate2.CreateFromPemFile($"{certsDir}/client.crt", $"{certsDir}/client.key");

// Validate service-b's server cert against the internal CA (the mutual half).
bool ValidateServer(HttpRequestMessage _, X509Certificate2? cert, X509Chain? __, System.Net.Security.SslPolicyErrors ___)
{
    if (cert is null) return false;
    var chain = new X509Chain();
    chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
    chain.ChainPolicy.CustomTrustStore.Add(caCert);
    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
    return chain.Build(new X509Certificate2(cert));
}

// HttpClient WITH the client certificate — for the authenticated call.
var trustedHandler = new HttpClientHandler
{
    ServerCertificateCustomValidationCallback = ValidateServer,
};
trustedHandler.ClientCertificates.Add(clientCert);
var trustedClient = new HttpClient(trustedHandler);

// HttpClient WITHOUT a client certificate — to prove the zero-trust rejection.
var untrustedHandler = new HttpClientHandler
{
    ServerCertificateCustomValidationCallback = ValidateServer,
};
var untrustedClient = new HttpClient(untrustedHandler);

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls($"http://0.0.0.0:{port}");
var app = builder.Build();

app.MapGet("/call", async () =>
{
    var resp = await trustedClient.GetStringAsync(target);
    // Forward service-b's body verbatim.
    return Results.Content(resp, "application/json");
});

app.MapGet("/call-no-cert", async () =>
{
    try
    {
        await untrustedClient.GetStringAsync(target);
        return Results.Json(new { status = "unexpected", authenticated = false }, statusCode: 500);
    }
    catch (HttpRequestException ex)
    {
        // Expected zero-trust outcome: handshake aborted by service-b.
        return Results.Json(new { status = "rejected", authenticated = false, reason = ex.Message }, statusCode: 502);
    }
});

Console.WriteLine($"[service-a] listening on :{port} -> {target}");
app.Run();
