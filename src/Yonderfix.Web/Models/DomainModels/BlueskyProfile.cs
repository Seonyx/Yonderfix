namespace Yonderfix.Web.Models.DomainModels;

public class BlueskyProfile
{
    public string Did { get; set; } = string.Empty;
    public string Handle { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string? AvatarUrl { get; set; }
    public int FollowersCount { get; set; }
    public int FollowsCount { get; set; }
    public string? FollowUri { get; set; } // at:// URI of follow record (for unfollow)
    public string DisplayLabel => string.IsNullOrEmpty(DisplayName) ? Handle : DisplayName;
}
