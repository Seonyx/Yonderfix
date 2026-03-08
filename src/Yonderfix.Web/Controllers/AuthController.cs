using Microsoft.AspNetCore.Mvc;
using Yonderfix.Web.Helpers;
using Yonderfix.Web.Models.ViewModels;
using Yonderfix.Web.Services;

namespace Yonderfix.Web.Controllers;

public class AuthController : BaseController
{
    private readonly BlueskyService _blueskyService;
    private readonly ILogger<AuthController> _logger;

    public AuthController(BlueskyService blueskyService, ILogger<AuthController> logger)
    {
        _blueskyService = blueskyService;
        _logger = logger;
    }

    [HttpGet]
    public IActionResult Login()
    {
        // If already logged in, go to dashboard
        if (HttpContext.Session.IsAuthenticated())
            return RedirectToAction("Index", "Dashboard");

        return View(new LoginViewModel());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model)
    {
        if (!ModelState.IsValid)
            return View(model);

        try
        {
            var handle = model.Handle.Trim();
            // Ensure handle doesn't have @ prefix
            if (handle.StartsWith("@"))
                handle = handle.Substring(1);

            var session = await _blueskyService.LoginAsync(handle, model.AppPassword);
            HttpContext.Session.SetUserSession(session);

            _logger.LogInformation("User {Handle} logged in successfully", handle);
            return RedirectToAction("Index", "Dashboard");
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogWarning("Login failed for {Handle}: {Message}", model.Handle, ex.Message);
            model.ErrorMessage = ex.Message;
            return View(model);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during login for {Handle}", model.Handle);
            model.ErrorMessage = "An unexpected error occurred. Please try again.";
            return View(model);
        }
    }

    [HttpGet]
    public IActionResult Logout()
    {
        HttpContext.Session.ClearUserSession();
        HttpContext.Session.Clear();
        return RedirectToAction("Login", "Auth");
    }
}
