using Yonderfix.Web.Models.DomainModels;

namespace Yonderfix.Web.Models.ViewModels;

public class ProfileListViewModel
{
    public List<BlueskyProfile> Profiles { get; set; } = new();
    public int CurrentPage { get; set; }
    public int TotalPages { get; set; }
    public int PageSize { get; set; }
    public int TotalCount { get; set; }
    public string PageTitle { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
}
