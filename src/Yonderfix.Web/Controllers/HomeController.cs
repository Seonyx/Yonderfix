using Microsoft.AspNetCore.Mvc;
using Yonderfix.Web.Helpers;

namespace Yonderfix.Web.Controllers;

public class HomeController : BaseController
{
    public IActionResult Index()
    {
        if (HttpContext.Session.IsAuthenticated())
            return RedirectToAction("Index", "Dashboard");

        return RedirectToAction("Login", "Auth");
    }

    public IActionResult Error()
    {
        return View();
    }
}
