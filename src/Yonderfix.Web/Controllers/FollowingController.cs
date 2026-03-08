using Microsoft.AspNetCore.Mvc;
using Yonderfix.Web.Filters;
using Yonderfix.Web.Helpers;
using Yonderfix.Web.Models.ViewModels;
using Yonderfix.Web.Services;

namespace Yonderfix.Web.Controllers;

[AuthenticationFilter]
public class FollowingController : BaseController
{
    private readonly FollowerAnalysisService _followerAnalysisService;
    private readonly BlueskyService _blueskyService;
    private readonly SettingsService _settingsService;
    private readonly ILogger<FollowingController> _logger;

    public FollowingController(
        FollowerAnalysisService followerAnalysisService,
        BlueskyService blueskyService,
        SettingsService settingsService,
        ILogger<FollowingController> logger)
    {
        _followerAnalysisService = followerAnalysisService;
        _blueskyService = blueskyService;
        _settingsService = settingsService;
        _logger = logger;
    }

    [HttpGet]
    public async Task<IActionResult> NotFollowingBack(int page = 1)
    {
        var session = HttpContext.Session.GetUserSession()!;
        var pageSize = _settingsService.PageSize;

        if (page < 1) page = 1;

        List<Models.DomainModels.BlueskyProfile> profiles;
        try
        {
            profiles = await _followerAnalysisService.GetNonMutualFollowsAsync(session.Did, session.AccessJwt);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error loading non-mutual follows for {Did}", session.Did);
            profiles = new();
            ViewBag.ErrorMessage = "Failed to load data. Please try again.";
        }

        var totalCount = profiles.Count;
        var totalPages = (int)Math.Ceiling(totalCount / (double)pageSize);
        if (page > totalPages && totalPages > 0) page = totalPages;

        var paged = profiles
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToList();

        var model = new ProfileListViewModel
        {
            Profiles = paged,
            CurrentPage = page,
            TotalPages = totalPages,
            PageSize = pageSize,
            TotalCount = totalCount,
            PageTitle = "Following Not Following Back",
            Description = "You follow these people, but they don't follow you back."
        };

        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Unfollow(string followUri, int returnPage = 1)
    {
        var session = HttpContext.Session.GetUserSession()!;

        try
        {
            await _blueskyService.UnfollowAsync(followUri, session.Did, session.AccessJwt);
            TempData["SuccessMessage"] = "Successfully unfollowed user.";
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error unfollowing {FollowUri}", followUri);
            TempData["ErrorMessage"] = "Failed to unfollow user. Please try again.";
        }

        return RedirectToAction("NotFollowingBack", new { page = returnPage });
    }
}
