using Microsoft.EntityFrameworkCore;

namespace Yonderfix.Web.Data;

public class YonderfixDbContext : DbContext
{
    public YonderfixDbContext(DbContextOptions<YonderfixDbContext> options)
        : base(options)
    {
    }

    public DbSet<ApplicationUser> Users => Set<ApplicationUser>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<ApplicationUser>(entity =>
        {
            entity.HasIndex(u => u.BlueskyDid).IsUnique();
            entity.HasIndex(u => u.BlueskyHandle);
            entity.Property(u => u.CreatedAt).HasDefaultValueSql("GETUTCDATE()");
        });
    }
}
