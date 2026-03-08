using Microsoft.AspNetCore.Mvc;
using Yonderfix.Web.Filters;
using Yonderfix.Web.Models.ViewModels;
using Yonderfix.Web.Services;

namespace Yonderfix.Web.Controllers;

[AuthenticationFilter]
public class AccountController : BaseController
{
    private readonly SettingsService _settingsService;

    public AccountController(SettingsService settingsService)
    {
        _settingsService = settingsService;
    }

    [HttpGet]
    public IActionResult Settings()
    {
        var settings = _settingsService.GetSettings();
        var model = new SettingsViewModel
        {
            PageSize = settings.PageSize
        };
        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult Settings(SettingsViewModel model)
    {
        if (!ModelState.IsValid)
            return View(model);

        _settingsService.UpdatePageSize(model.PageSize);
        model.SuccessMessage = "Settings saved successfully.";
        return View(model);
    }
}
