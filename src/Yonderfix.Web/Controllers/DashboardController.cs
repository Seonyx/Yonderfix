using Microsoft.AspNetCore.Mvc;
using Yonderfix.Web.Filters;
using Yonderfix.Web.Helpers;
using Yonderfix.Web.Models.ViewModels;
using Yonderfix.Web.Services;

namespace Yonderfix.Web.Controllers;

[AuthenticationFilter]
public class DashboardController : BaseController
{
    private readonly BlueskyService _blueskyService;
    private readonly ILogger<DashboardController> _logger;

    public DashboardController(BlueskyService blueskyService, ILogger<DashboardController> logger)
    {
        _blueskyService = blueskyService;
        _logger = logger;
    }

    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var session = HttpContext.Session.GetUserSession()!;

        int followersCount = 0;
        int followsCount = 0;
        int mutualCount = 0;

        try
        {
            var followsTask = _blueskyService.GetFollowsAsync(session.Did, session.AccessJwt);
            var followerDidsTask = _blueskyService.GetFollowerDidsAsync(session.Did, session.AccessJwt);

            await Task.WhenAll(followsTask, followerDidsTask);

            var follows = await followsTask;
            var followerDids = await followerDidsTask;

            followsCount = follows.Count;
            followersCount = followerDids.Count;
            mutualCount = follows.Count(f => followerDids.Contains(f.Did));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error loading dashboard stats for {Did}", session.Did);
            // Proceed with zeroes - don't crash the dashboard
        }

        var model = new DashboardViewModel
        {
            Handle = session.Handle,
            DisplayName = string.IsNullOrEmpty(session.DisplayName) ? session.Handle : session.DisplayName,
            AvatarUrl = session.AvatarUrl,
            FollowersCount = followersCount,
            FollowsCount = followsCount,
            MutualCount = mutualCount,
            NotFollowingBackCount = followersCount - mutualCount,
            NotFollowedBackCount = followsCount - mutualCount
        };

        return View(model);
    }
}
