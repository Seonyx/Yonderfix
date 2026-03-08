using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Yonderfix.Web.Helpers;

namespace Yonderfix.Web.Controllers;

public abstract class BaseController : Controller
{
    public override void OnActionExecuting(ActionExecutingContext context)
    {
        ViewBag.IsAuthenticated = HttpContext.Session.IsAuthenticated();
        base.OnActionExecuting(context);
    }
}
