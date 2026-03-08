namespace Yonderfix.Web.Models.ViewModels;

public class DashboardViewModel
{
    public string Handle { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string? AvatarUrl { get; set; }
    public int FollowersCount { get; set; }
    public int FollowsCount { get; set; }
    public int MutualCount { get; set; }
}
