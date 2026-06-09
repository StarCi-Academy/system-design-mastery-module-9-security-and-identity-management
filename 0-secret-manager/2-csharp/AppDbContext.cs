using Microsoft.EntityFrameworkCore;

namespace SecretApi;

public class User
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
}

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<User> Users => Set<User>();
}
