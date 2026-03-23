namespace Yonderfix.Web.Models.ViewModels;

public class DashboardViewModel
{
    public string Handle { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string? AvatarUrl { get; set; }
    public int FollowersCount { get; set; }
    public int FollowsCount { get; set; }
    public int MutualCount { get; set; }
    public int NotFollowingBackCount { get; set; }   // follow you, you don't follow back
    public int NotFollowedBackCount { get; set; }    // you follow, they don't follow back
}
