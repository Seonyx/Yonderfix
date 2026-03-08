namespace Yonderfix.Web.Models.DomainModels;

public class UserSession
{
    public string Did { get; set; } = string.Empty;
    public string Handle { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string? AvatarUrl { get; set; }
    public string AccessJwt { get; set; } = string.Empty;
    public string RefreshJwt { get; set; } = string.Empty;
}
