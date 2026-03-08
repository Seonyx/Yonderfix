using System.Text.Json;
using Yonderfix.Web.Models.DomainModels;

namespace Yonderfix.Web.Helpers;

public static class SessionHelper
{
    private const string SessionKey = "UserSession";

    public static void SetUserSession(this ISession session, UserSession userSession)
    {
        var json = JsonSerializer.Serialize(userSession);
        session.SetString(SessionKey, json);
    }

    public static UserSession? GetUserSession(this ISession session)
    {
        var json = session.GetString(SessionKey);
        if (string.IsNullOrEmpty(json))
            return null;

        try
        {
            return JsonSerializer.Deserialize<UserSession>(json);
        }
        catch
        {
            return null;
        }
    }

    public static void ClearUserSession(this ISession session)
    {
        session.Remove(SessionKey);
    }

    public static bool IsAuthenticated(this ISession session)
    {
        return !string.IsNullOrEmpty(session.GetString(SessionKey));
    }
}
