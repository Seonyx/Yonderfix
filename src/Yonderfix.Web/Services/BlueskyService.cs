using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Yonderfix.Web.Models.DomainModels;

namespace Yonderfix.Web.Services;

public class BlueskyService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly string _baseUrl;
    private readonly ILogger<BlueskyService> _logger;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    public BlueskyService(IHttpClientFactory httpClientFactory, IConfiguration configuration, ILogger<BlueskyService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _baseUrl = configuration["BlueskyApi:BaseUrl"] ?? "https://bsky.social/xrpc";
        _logger = logger;
    }

    public async Task<UserSession> LoginAsync(string handle, string appPassword)
    {
        var client = _httpClientFactory.CreateClient("BlueskyClient");

        var payload = new
        {
            identifier = handle,
            password = appPassword
        };

        var json = JsonSerializer.Serialize(payload);
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        var response = await client.PostAsync($"{_baseUrl}/com.atproto.server.createSession", content);
        var responseBody = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogWarning("Login failed for {Handle}: {StatusCode} {Body}", handle, response.StatusCode, responseBody);

            // Try to extract Bluesky's own error message from the response body
            string errorMessage = response.StatusCode == System.Net.HttpStatusCode.Unauthorized
                ? "Invalid handle or app password. Check your credentials and try again."
                : $"Sign in failed ({(int)response.StatusCode}).";

            try
            {
                using var errDoc = JsonDocument.Parse(responseBody);
                if (errDoc.RootElement.TryGetProperty("message", out var msgProp))
                {
                    var blueskyMsg = msgProp.GetString();
                    if (!string.IsNullOrWhiteSpace(blueskyMsg))
                        errorMessage = blueskyMsg;
                }
            }
            catch { /* ignore JSON parse errors on error responses */ }

            throw new InvalidOperationException(errorMessage);
        }

        using var doc = JsonDocument.Parse(responseBody);
        var root = doc.RootElement;

        var session = new UserSession
        {
            Did = root.GetProperty("did").GetString() ?? string.Empty,
            Handle = root.GetProperty("handle").GetString() ?? string.Empty,
            AccessJwt = root.GetProperty("accessJwt").GetString() ?? string.Empty,
            RefreshJwt = root.GetProperty("refreshJwt").GetString() ?? string.Empty
        };

        // displayName may not be present
        if (root.TryGetProperty("displayName", out var displayNameProp))
            session.DisplayName = displayNameProp.GetString() ?? string.Empty;

        return session;
    }

    public async Task<List<BlueskyProfile>> GetFollowsAsync(string did, string accessJwt)
    {
        var client = _httpClientFactory.CreateClient("BlueskyClient");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessJwt);

        var follows = new List<BlueskyProfile>();
        string? cursor = null;

        do
        {
            var url = $"{_baseUrl}/app.bsky.graph.getFollows?actor={Uri.EscapeDataString(did)}&limit=100";
            if (cursor != null)
                url += $"&cursor={Uri.EscapeDataString(cursor)}";

            var response = await client.GetAsync(url);
            var body = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("GetFollows failed: {StatusCode} {Body}", response.StatusCode, body);
                break;
            }

            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;

            if (root.TryGetProperty("follows", out var followsArr))
            {
                foreach (var item in followsArr.EnumerateArray())
                {
                    var profile = new BlueskyProfile
                    {
                        Did = item.TryGetProperty("did", out var didProp) ? didProp.GetString() ?? string.Empty : string.Empty,
                        Handle = item.TryGetProperty("handle", out var handleProp) ? handleProp.GetString() ?? string.Empty : string.Empty,
                        DisplayName = item.TryGetProperty("displayName", out var dnProp) ? dnProp.GetString() ?? string.Empty : string.Empty,
                        AvatarUrl = item.TryGetProperty("avatar", out var avatarProp) ? avatarProp.GetString() : null
                    };

                    // Extract viewer.following URI for unfollow
                    if (item.TryGetProperty("viewer", out var viewer) &&
                        viewer.TryGetProperty("following", out var followingProp))
                    {
                        profile.FollowUri = followingProp.GetString();
                    }

                    follows.Add(profile);
                }
            }

            cursor = null;
            if (root.TryGetProperty("cursor", out var cursorProp))
                cursor = cursorProp.GetString();

        } while (!string.IsNullOrEmpty(cursor));

        return follows;
    }

    public async Task<HashSet<string>> GetFollowerDidsAsync(string did, string accessJwt)
    {
        var client = _httpClientFactory.CreateClient("BlueskyClient");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessJwt);

        var dids = new HashSet<string>();
        string? cursor = null;

        do
        {
            var url = $"{_baseUrl}/app.bsky.graph.getFollowers?actor={Uri.EscapeDataString(did)}&limit=100";
            if (cursor != null)
                url += $"&cursor={Uri.EscapeDataString(cursor)}";

            var response = await client.GetAsync(url);
            var body = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("GetFollowers failed: {StatusCode} {Body}", response.StatusCode, body);
                break;
            }

            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;

            if (root.TryGetProperty("followers", out var followersArr))
            {
                foreach (var item in followersArr.EnumerateArray())
                {
                    if (item.TryGetProperty("did", out var didProp))
                    {
                        var followerDid = didProp.GetString();
                        if (!string.IsNullOrEmpty(followerDid))
                            dids.Add(followerDid);
                    }
                }
            }

            cursor = null;
            if (root.TryGetProperty("cursor", out var cursorProp))
                cursor = cursorProp.GetString();

        } while (!string.IsNullOrEmpty(cursor));

        return dids;
    }

    public async Task<List<BlueskyProfile>> GetFollowersAsync(string did, string accessJwt)
    {
        var client = _httpClientFactory.CreateClient("BlueskyClient");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessJwt);

        var followers = new List<BlueskyProfile>();
        string? cursor = null;

        do
        {
            var url = $"{_baseUrl}/app.bsky.graph.getFollowers?actor={Uri.EscapeDataString(did)}&limit=100";
            if (cursor != null)
                url += $"&cursor={Uri.EscapeDataString(cursor)}";

            var response = await client.GetAsync(url);
            var body = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("GetFollowers failed: {StatusCode} {Body}", response.StatusCode, body);
                break;
            }

            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;

            if (root.TryGetProperty("followers", out var followersArr))
            {
                foreach (var item in followersArr.EnumerateArray())
                {
                    var profile = new BlueskyProfile
                    {
                        Did = item.TryGetProperty("did", out var didProp) ? didProp.GetString() ?? string.Empty : string.Empty,
                        Handle = item.TryGetProperty("handle", out var handleProp) ? handleProp.GetString() ?? string.Empty : string.Empty,
                        DisplayName = item.TryGetProperty("displayName", out var dnProp) ? dnProp.GetString() ?? string.Empty : string.Empty,
                        AvatarUrl = item.TryGetProperty("avatar", out var avatarProp) ? avatarProp.GetString() : null
                    };
                    followers.Add(profile);
                }
            }

            cursor = null;
            if (root.TryGetProperty("cursor", out var cursorProp))
                cursor = cursorProp.GetString();

        } while (!string.IsNullOrEmpty(cursor));

        return followers;
    }

    public async Task UnfollowAsync(string followUri, string did, string accessJwt)
    {
        // at://did:plc:xxx/app.bsky.graph.follow/rkey
        var rkey = followUri.Split('/').LastOrDefault() ?? string.Empty;

        var client = _httpClientFactory.CreateClient("BlueskyClient");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessJwt);

        var payload = new
        {
            repo = did,
            collection = "app.bsky.graph.follow",
            rkey = rkey
        };

        var json = JsonSerializer.Serialize(payload);
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        var response = await client.PostAsync($"{_baseUrl}/com.atproto.repo.deleteRecord", content);
        var body = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogWarning("Unfollow failed for {FollowUri}: {StatusCode} {Body}", followUri, response.StatusCode, body);
            throw new InvalidOperationException($"Unfollow failed: {response.StatusCode}");
        }
    }

    public async Task FollowAsync(string targetDid, string sourceDid, string accessJwt)
    {
        var client = _httpClientFactory.CreateClient("BlueskyClient");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessJwt);

        var payload = new
        {
            repo = sourceDid,
            collection = "app.bsky.graph.follow",
            record = new
            {
                @type = "app.bsky.graph.follow",
                subject = targetDid,
                createdAt = DateTime.UtcNow.ToString("o")
            }
        };

        var json = JsonSerializer.Serialize(payload);
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        var response = await client.PostAsync($"{_baseUrl}/com.atproto.repo.createRecord", content);
        var body = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogWarning("Follow failed for target {TargetDid}: {StatusCode} {Body}", targetDid, response.StatusCode, body);
            throw new InvalidOperationException($"Follow failed: {response.StatusCode}");
        }
    }
}
