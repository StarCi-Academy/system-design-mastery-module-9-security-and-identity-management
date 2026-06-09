using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Https;

// service-b — the mTLS server. Kestrel is configured to REQUIRE a client certificate
// and we verify it chains to the internal CA. No valid cert => the TLS handshake is
// rejected before any endpoint runs (zero-trust at the transport layer).
var certsDir = Environment.GetEnvironmentVariable("CERTS_DIR") ?? "/certs";
var port = int.Parse(Environment.GetEnvironmentVariable("PORT") ?? "8443");

// The internal CA used to validate the presented client certificate.
var caCert = new X509Certificate2($"{certsDir}/ca.crt");
var serverCert = X509Certificate2.CreateFromPemFile($"{certsDir}/server.crt", $"{certsDir}/server.key");

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenAnyIP(port, listen =>
    {
        listen.UseHttps(serverCert, https =>
        {
            https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
            https.ClientCertificateValidation = (clientCert, chain, errors) =>
            {
                // Trust ONLY certificates that chain to our internal CA.
                var customChain = new X509Chain();
                customChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                customChain.ChainPolicy.CustomTrustStore.Add(caCert);
                customChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                return customChain.Build(clientCert);
            };
        });
    });
});

var app = builder.Build();

app.MapGet("/secure", (HttpContext ctx) =>
{
    // Reaching here proves the client cert already passed CA verification.
    var clientCert = ctx.Connection.ClientCertificate;
    var caller = clientCert?.GetNameInfo(X509NameType.SimpleName, false) ?? "unknown";
    return Results.Json(new { status = "ok", caller, authenticated = true });
});

Console.WriteLine($"[service-b] mTLS server listening on :{port} (RequireCertificate + CA validation)");
app.Run();
