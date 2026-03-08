using System.ComponentModel.DataAnnotations;

namespace Yonderfix.Web.Data;

public class ApplicationUser
{
    [Key]
    public int Id { get; set; }

    [Required]
    [MaxLength(200)]
    public string BlueskyHandle { get; set; } = string.Empty;

    [Required]
    [MaxLength(200)]
    public string BlueskyDid { get; set; } = string.Empty;

    [MaxLength(200)]
    public string? DisplayName { get; set; }

    public DateTime? LastLoginAt { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
