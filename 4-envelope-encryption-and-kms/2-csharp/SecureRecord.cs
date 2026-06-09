using Microsoft.EntityFrameworkCore;

namespace EnvelopeApi;

/// <summary>
/// Stores ONLY ciphertext + the wrapped DEK. No plaintext, no raw DEK — a DB dump is
/// useless without the KEK held in Vault Transit.
/// </summary>
public class SecureRecord
{
    public int Id { get; set; }
    public string WrappedDek { get; set; } = "";
    public string Iv { get; set; } = "";
    public string Ciphertext { get; set; } = "";
}

public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<SecureRecord> SecureRecords => Set<SecureRecord>();
}
