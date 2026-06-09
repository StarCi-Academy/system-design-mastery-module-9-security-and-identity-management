using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using VaultSharp;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.SecretsEngines.Transit;

namespace EnvelopeApi;

public record Envelope(string WrappedDek, string Iv, string Ciphertext);

/// <summary>
/// Two-tier envelope encryption:
///   data ──AES-256-GCM──▶ encrypted by a per-record DEK (generated locally)
///   DEK  ──Transit wrap──▶ encrypted by the KEK (lives only in Vault)
/// Bulk data never touches Vault; only the 32-byte DEK is wrapped/unwrapped.
/// </summary>
public class EnvelopeService
{
    private readonly IVaultClient _vault;
    private readonly HttpClient _http;
    private readonly string _addr;
    private readonly string _token;
    private readonly string _kek;

    public EnvelopeService(string addr, string token, string kek)
    {
        _addr = addr;
        _token = token;
        _kek = kek;
        _vault = new VaultClient(new VaultClientSettings(addr, new TokenAuthMethodInfo(token)));
        _http = new HttpClient { BaseAddress = new Uri(addr) };
        _http.DefaultRequestHeaders.Add("X-Vault-Token", token);
    }

    /// <summary>Enable Transit and create the KEK (idempotent) at boot.</summary>
    public async Task EnsureKekAsync()
    {
        await PostRawAsync($"/v1/sys/mounts/transit", new { type = "transit" });
        await PostRawAsync($"/v1/transit/keys/{_kek}", new { type = "aes256-gcm96" });
    }

    public async Task<Envelope> EncryptAsync(string plaintext)
    {
        // 1. Fresh 256-bit DEK + 96-bit GCM nonce for THIS record only.
        var dek = RandomNumberGenerator.GetBytes(32);
        var iv = RandomNumberGenerator.GetBytes(12);

        // 2. Encrypt the bulk data locally with AES-256-GCM — Vault never sees the plaintext.
        var plainBytes = Encoding.UTF8.GetBytes(plaintext);
        var cipherBytes = new byte[plainBytes.Length];
        var tag = new byte[16];
        using (var aes = new AesGcm(dek, 16))
        {
            aes.Encrypt(iv, plainBytes, cipherBytes, tag);
        }
        var sealedBytes = cipherBytes.Concat(tag).ToArray(); // ciphertext||authTag

        // 3. Wrap the DEK with the KEK inside Vault.
        var enc = await _vault.V1.Secrets.Transit.EncryptAsync(_kek, new EncryptRequestOptions
        {
            Base64EncodedPlainText = Convert.ToBase64String(dek)
        });

        return new Envelope(enc.Data.CipherText, Convert.ToBase64String(iv), Convert.ToBase64String(sealedBytes));
    }

    public async Task<string> DecryptAsync(string wrappedDek, string ivB64, string ctB64)
    {
        // 1. Ask Vault to unwrap the DEK (works across KEK versions after rotation).
        var dec = await _vault.V1.Secrets.Transit.DecryptAsync(_kek, new DecryptRequestOptions
        {
            CipherText = wrappedDek
        });
        var dek = Convert.FromBase64String(dec.Data.Base64EncodedPlainText);
        var iv = Convert.FromBase64String(ivB64);
        var sealedBytes = Convert.FromBase64String(ctB64);

        // 2. Decrypt locally with the recovered DEK.
        var cipherLen = sealedBytes.Length - 16;
        var cipherBytes = sealedBytes[..cipherLen];
        var tag = sealedBytes[cipherLen..];
        var plain = new byte[cipherLen];
        using var aes = new AesGcm(dek, 16);
        aes.Decrypt(iv, cipherBytes, tag, plain);
        return Encoding.UTF8.GetString(plain);
    }

    public async Task<int> RotateKekAsync()
    {
        await PostRawAsync($"/v1/transit/keys/{_kek}/rotate", new { });
        using var resp = await _http.GetAsync($"/v1/transit/keys/{_kek}");
        var json = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("data").GetProperty("latest_version").GetInt32();
    }

    public async Task ShredKekAsync()
    {
        // Crypto-shredding: allow deletion, then delete the KEK so no DEK can be unwrapped again.
        await PostRawAsync($"/v1/transit/keys/{_kek}/config", new { deletion_allowed = true });
        await _http.DeleteAsync($"/v1/transit/keys/{_kek}");
    }

    private async Task PostRawAsync(string path, object body)
    {
        var content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
        await _http.PostAsync(path, content); // ignore "already exists" / "already mounted"
    }
}
