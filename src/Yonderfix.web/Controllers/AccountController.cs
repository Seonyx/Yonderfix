using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using Yonderfix.web.Services;
using Microsoft.AspNetCore.Http; // Required for IHttpContextAccessor and Session
using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Logging; // Required for ILogger

namespace Yonderfix.web.Controllers
{
    [Route("[controller]/[action]")]
    public class AccountController : Controller
    {
        private readonly BlueskyService _blueskyService;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly ILogger<AccountController> _logger;

        public AccountController(BlueskyService blueskyService, IHttpContextAccessor httpContextAccessor, ILogger<AccountController> logger)
        {
            _blueskyService = blueskyService;
            _httpContextAccessor = httpContextAccessor;
            _logger = logger;
        }

        [HttpGet]
        public async Task<IActionResult> Login(string loginHint = null)
        {
            try
            {
                _logger.LogInformation("Login action called. Login hint: {LoginHint}", loginHint ?? "N/A");
                string redirectUrl = await _blueskyService.StartAuthorizationFlowAsync(loginHint);
                _logger.LogInformation("Redirecting to Bluesky authorization URL for login hint: {LoginHint}", loginHint ?? "N/A");
                return Redirect(redirectUrl);
            }
            catch (System.Exception ex)
            {
                _logger.LogError(ex, "Error during login initiation for login hint: {LoginHint}.", loginHint ?? "N/A");
                // It's often better to show a generic error to the user and rely on logs for details.
                return View("Error", new { Message = "Sorry, we couldn't start the login process. Please try again later." });
            }
        }

        [HttpGet]
        public async Task<IActionResult> Logout()
        {
            var userDid = User.FindFirstValue(ClaimTypes.NameIdentifier); // Get UserDID before sign out
            _logger.LogInformation("Logout action called for UserDID: {UserDid}", userDid ?? "Unknown");

            // Clear local application session
            _httpContextAccessor.HttpContext.Session.Clear();
            _logger.LogDebug("Session cleared for UserDID: {UserDid}", userDid ?? "Unknown");

            // Sign out from the cookie authentication scheme
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            _logger.LogInformation("User {UserDid} logged out successfully.", userDid ?? "Unknown");
            return RedirectToAction("Index", "Home");
        }

        // Callback action to handle the OAuth response.
        [HttpGet]
        public async Task<IActionResult> Callback(string code, string state) // 'iss' is not typically used directly here unless for multi-issuer validation
        {
            if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(state))
            {
                _logger.LogWarning("OAuth callback received with missing code or state parameters. Code: {CodeProvided}, State: {StateProvided}", !string.IsNullOrEmpty(code), !string.IsNullOrEmpty(state));
                return BadRequest("Authorization code or state parameter is missing from the callback.");
            }

            _logger.LogInformation("OAuth callback received. State: {State}, Code provided: {CodeProvided}", state, !string.IsNullOrEmpty(code));

            var expectedState = _httpContextAccessor.HttpContext.Session.GetString($"oauth_state_{state}");
            if (string.IsNullOrEmpty(expectedState))
            {
                _logger.LogError("OAuth callback state validation failed: No expected state found in session for received state {ReceivedState}. Possible session expiry or tampering attempt.", state);
                return BadRequest("Invalid state or session expired. Please try logging in again.");
            }

            if (expectedState != state)
            {
                _logger.LogError("OAuth callback state mismatch. Expected: {ExpectedState}, Received: {ReceivedState}. Possible CSRF attack.", expectedState, state);
                return BadRequest("State mismatch. Please try logging in again to ensure security.");
            }

            _logger.LogInformation("OAuth callback state validation successful for state: {State}", state);

            try
            {
                var tokens = await _blueskyService.ExchangeCodeForTokensAsync(code, state);

                if (tokens == null || string.IsNullOrEmpty(tokens.AccessToken) || string.IsNullOrEmpty(tokens.UserDid))
                {
                    _logger.LogError("Token exchange process completed but resulted in null tokens or missing AccessToken/UserDid for state: {State}. Token object: {@Tokens}", state, tokens);
                    return View("Error", new { Message = "Failed to retrieve valid authentication tokens from Bluesky. Please try again." });
                }

                _logger.LogInformation("Token exchange successful for UserDID: {UserDid} (State: {State}).", tokens.UserDid, state);

                // Store tokens in session
                _httpContextAccessor.HttpContext.Session.SetString("access_token", tokens.AccessToken);
                    if (!string.IsNullOrEmpty(tokens.RefreshToken))
                    {
                        _httpContextAccessor.HttpContext.Session.SetString("refresh_token", tokens.RefreshToken);
                    }
                    _httpContextAccessor.HttpContext.Session.SetString("user_did", tokens.UserDid);
                    _logger.LogInformation("Tokens stored in session for User DID: {UserDid}", tokens.UserDid);

                    // Create claims and sign in user
                    var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.NameIdentifier, tokens.UserDid),
                        new Claim("access_token", tokens.AccessToken),
                        new Claim("urn:bluesky:did", tokens.UserDid)
                        // Add other claims as needed, e.g., scope
                    };
                    if (!string.IsNullOrEmpty(tokens.Scope))
                    {
                        claims.Add(new Claim("scope", tokens.Scope));
                    }

                    var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme); // Use scheme name
                    var authProperties = new AuthenticationProperties
                    {
                        IsPersistent = true, // Make cookie persistent
                        ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(60) // Example expiration
                        // Store tokens in auth properties if desired and if using cookies for session
                        // This is useful if you want the tokens to be available in HttpContext.GetTokenAsync(...)
                        // authProperties.StoreTokens(new[]
                        // {
                        //     new AuthenticationToken { Name = "access_token", Value = tokens.AccessToken },
                        //     new AuthenticationToken { Name = "refresh_token", Value = tokens.RefreshToken }
                        // });
                    };

                    await HttpContext.SignInAsync(
                        CookieAuthenticationDefaults.AuthenticationScheme, // Use scheme name
                        new ClaimsPrincipal(claimsIdentity),
                        authProperties);

                    _logger.LogInformation("User {UserDid} signed in successfully with cookie authentication.", tokens.UserDid);

                    // Redirect to a logged-in page or home
                    return RedirectToAction("Index", "Home");
                }
                // This else block should ideally not be reached if the null/empty check above is comprehensive.
                // Kept for defensive programming, though BlueskyService should throw before this if tokens are invalid.
                 _logger.LogError("Token exchange failed or returned invalid tokens for state: {State}. Token object: {@Tokens}", state, tokens);
                 return View("Error", new { Message = "Login failed: Could not obtain valid tokens." });
            }
            catch (System.Exception ex)
            {
                _logger.LogError(ex, "Exception during OAuth callback processing (token exchange or sign-in) for state: {State}.", state);
                return View("Error", new { Message = "An unexpected error occurred during login. Please try again." });
            }
        }
    }
}
