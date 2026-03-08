using Microsoft.AspNetCore.Mvc;
using Yonderfix.Web.Filters;
using Yonderfix.Web.Helpers;
using Yonderfix.Web.Models.ViewModels;
using Yonderfix.Web.Services;

namespace Yonderfix.Web.Controllers;

[AuthenticationFilter]
public class FollowersController : BaseController
{
    private readonly FollowerAnalysisService _followerAnalysisService;
    private readonly BlueskyService _blueskyService;
    private readonly SettingsService _settingsService;
    private readonly ILogger<FollowersController> _logger;

    public FollowersController(
        FollowerAnalysisService followerAnalysisService,
        BlueskyService blueskyService,
        SettingsService settingsService,
        ILogger<FollowersController> logger)
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
            profiles = await _followerAnalysisService.GetNotFollowingBackAsync(session.Did, session.AccessJwt);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error loading followers not following back for {Did}", session.Did);
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
            PageTitle = "Followers Not Following Back",
            Description = "These people follow you, but you don't follow them back."
        };

        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> FollowBack(string did, int returnPage = 1)
    {
        var session = HttpContext.Session.GetUserSession()!;

        try
        {
            await _blueskyService.FollowAsync(did, session.Did, session.AccessJwt);
            TempData["SuccessMessage"] = "Successfully followed user.";
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error following {TargetDid}", did);
            TempData["ErrorMessage"] = "Failed to follow user. Please try again.";
        }

        return RedirectToAction("NotFollowingBack", new { page = returnPage });
    }
}
