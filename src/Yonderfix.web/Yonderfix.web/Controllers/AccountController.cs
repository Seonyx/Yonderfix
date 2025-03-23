using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using Yonderfix.web.Services;  // This now includes BlueskyService

namespace Yonderfix.web.Controllers
{
    [Route("[controller]/[action]")]
    public class AccountController : Controller
    {
        private readonly BlueskyService _blueskyService;

        public AccountController(BlueskyService blueskyService)
        {
            _blueskyService = blueskyService;
        }

        [HttpGet]
        public async Task<IActionResult> Login(string loginHint = null)
        {
            // Start the OAuth flow (generate state, PKCE, PAR, etc.).
            string redirectUrl = await _blueskyService.StartAuthorizationFlowAsync(loginHint);
            // Redirect the user to the Authorization Server (PDS/entryway)
            return Redirect(redirectUrl);
        }

        [HttpGet]
        public IActionResult Logout()
        {
            // Sign out logic (clear cookies, tokens, etc.)
            return SignOut(new Microsoft.AspNetCore.Authentication.AuthenticationProperties { RedirectUri = "/" }, "Cookies", "Bluesky");
        }

        // Callback action to handle the OAuth response.
        [HttpGet]
        public async Task<IActionResult> Callback(string code, string state, string iss)
        {
            // TODO: Validate state, retrieve PKCE verifier, generate DPoP proof, exchange code for tokens, etc.
            return Content($"Code: {code}\nState: {state}\nIssuer: {iss}");
        }
    }
}
