using Yonderfix.Web.Models.DomainModels;

namespace Yonderfix.Web.Services;

public class FollowerAnalysisService
{
    private readonly BlueskyService _blueskyService;
    private readonly ILogger<FollowerAnalysisService> _logger;

    public FollowerAnalysisService(BlueskyService blueskyService, ILogger<FollowerAnalysisService> logger)
    {
        _blueskyService = blueskyService;
        _logger = logger;
    }

    /// <summary>
    /// Returns profiles who follow you, but you don't follow back.
    /// </summary>
    public async Task<List<BlueskyProfile>> GetNotFollowingBackAsync(string did, string accessJwt)
    {
        // Get the DIDs of people the user follows
        var followsDidsTask = _blueskyService.GetFollowsAsync(did, accessJwt);
        // Get full follower profiles
        var followersTask = _blueskyService.GetFollowersAsync(did, accessJwt);

        await Task.WhenAll(followsDidsTask, followersTask);

        var followsDids = (await followsDidsTask).Select(f => f.Did).ToHashSet();
        var followers = await followersTask;

        // Followers NOT in your follows list = they follow you, you don't follow them
        return followers
            .Where(f => !followsDids.Contains(f.Did))
            .OrderBy(f => f.DisplayLabel)
            .ToList();
    }

    /// <summary>
    /// Returns profiles you follow, but who don't follow you back (non-mutuals).
    /// </summary>
    public async Task<List<BlueskyProfile>> GetNonMutualFollowsAsync(string did, string accessJwt)
    {
        // Get full follow profiles (includes FollowUri for unfollow)
        var followsTask = _blueskyService.GetFollowsAsync(did, accessJwt);
        // Get set of DIDs who follow you
        var followerDidsTask = _blueskyService.GetFollowerDidsAsync(did, accessJwt);

        await Task.WhenAll(followsTask, followerDidsTask);

        var follows = await followsTask;
        var followerDids = await followerDidsTask;

        // People you follow who are NOT in your followers list
        return follows
            .Where(f => !followerDids.Contains(f.Did))
            .OrderBy(f => f.DisplayLabel)
            .ToList();
    }
}
