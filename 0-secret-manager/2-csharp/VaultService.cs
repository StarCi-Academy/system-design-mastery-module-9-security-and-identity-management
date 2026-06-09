using VaultSharp;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.Commons;

namespace SecretApi;

// Reads DB_PASSWORD from HashiCorp Vault (KV v2) at runtime, not from a static env var.
public class VaultService
{
    private readonly ILogger<VaultService> _logger;

    public VaultService(ILogger<VaultService> logger) => _logger = logger;

    public async Task<string> FetchDatabasePasswordAsync()
    {
        var vaultAddr = Environment.GetEnvironmentVariable("VAULT_ADDR") ?? "http://localhost:8200";
        var vaultToken = Environment.GetEnvironmentVariable("VAULT_TOKEN") ?? "root";
        _logger.LogInformation("Fetching secret from Vault at {Addr}/v1/secret/data/my-app...", vaultAddr);

        // Read the secret over Vault's HTTP API at runtime, not from a static env var.
        IAuthMethodInfo authMethod = new TokenAuthMethodInfo(vaultToken);
        var client = new VaultClient(new VaultClientSettings(vaultAddr, authMethod));
        Secret<SecretData> secret = await client.V1.Secrets.KeyValue.V2
            .ReadSecretAsync(path: "my-app", mountPoint: "secret");

        // KV v2 wraps the payload twice: SecretData.Data = values, SecretData.Metadata = version.
        if (!secret.Data.Data.TryGetValue("DB_PASSWORD", out var password) || password is null)
        {
            throw new InvalidOperationException("DB_PASSWORD not found in Vault secret.");
        }
        _logger.LogInformation("Successfully retrieved DB_PASSWORD from Vault.");
        return password.ToString()!;
    }
}
