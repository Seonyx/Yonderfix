using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Yonderfix.web.Helpers;         // For PkceUtil and DpopUtil
using Yonderfix.web.Models;           // Ensure Subscriber is defined here

namespace Yonderfix.web.Services
{
    public class BlueskyService
    {
        private readonly HttpClient _httpClient;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IConfiguration _configuration;
        private readonly ILogger<BlueskyService> _logger;

        // Configuration values for OAuth flow.
        private readonly string _clientId;
        private readonly string _redirectUri; // e.g. "https://localhost:7056/oauth/callback"
        private readonly string _parEndpoint;   // Pushed Authorization Request endpoint
        private readonly string _authEndpoint;  // Authorization endpoint

        public BlueskyService(HttpClient httpClient, IConfiguration configuration, ILogger<BlueskyService> logger, IHttpContextAccessor httpContextAccessor)
        {
            _httpClient = httpClient;
            _configuration = configuration;
            _logger = logger;
            _httpContextAccessor = httpContextAccessor;

            _clientId = _configuration["Authentication:Bluesky:ClientId"];
            _redirectUri = _configuration["Authentication:Bluesky:RedirectUri"];
            _parEndpoint = _configuration["Authentication:Bluesky:PushedAuthorizationRequestEndpoint"];
            _authEndpoint = _configuration["Authentication:Bluesky:AuthorizationEndpoint"];
        }

        /// <summary>
        /// Starts the OAuth flow by generating state, PKCE values, and making the PAR request.
        /// Returns the URL to which the client should be redirected.
        /// </summary>
        public async Task<string> StartAuthorizationFlowAsync(string loginHint = null)
        {
            // Generate state and PKCE values.
            string state = Guid.NewGuid().ToString("N");
            string codeVerifier = PkceUtil.GenerateCodeVerifier();
            string codeChallenge = PkceUtil.GenerateCodeChallenge(codeVerifier);

            // In a real application, store state and codeVerifier securely for later validation.
            var parParameters = new[]
            {
                $"client_id={Uri.EscapeDataString(_clientId)}",
                $"redirect_uri={Uri.EscapeDataString(_redirectUri)}",
                $"response_type=code",
                $"scope={Uri.EscapeDataString("atproto transition:generic")}",
                $"state={Uri.EscapeDataString(state)}",
                $"code_challenge={Uri.EscapeDataString(codeChallenge)}",
                $"code_challenge_method=S256"
            };

            if (!string.IsNullOrEmpty(loginHint))
            {
                parParameters = Append(parParameters, $"login_hint={Uri.EscapeDataString(loginHint)}");
            }

            string parRequestBody = string.Join("&", parParameters);
            var content = new StringContent(parRequestBody, Encoding.UTF8, "application/x-www-form-urlencoded");

            // Generate a DPoP proof for the PAR request.
            string dpopProof = DpopUtil.GenerateDpopProof(_parEndpoint, "POST");
            content.Headers.Add("DPoP", dpopProof);

            // Make the PAR request.
            var response = await _httpClient.PostAsync(_parEndpoint, content);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("PAR request failed: {StatusCode} {ReasonPhrase}", response.StatusCode, response.ReasonPhrase);
                throw new Exception("Pushed Authorization Request failed.");
            }

            // Parse the PAR response to retrieve the request_uri.
            var jsonResponse = await response.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(jsonResponse);
            if (!doc.RootElement.TryGetProperty("request_uri", out var requestUriElement))
            {
                throw new Exception("PAR response did not contain a request_uri.");
            }
            string requestUri = requestUriElement.GetString();
            string redirectUrl = $"{_authEndpoint}?client_id={Uri.EscapeDataString(_clientId)}&request_uri={Uri.EscapeDataString(requestUri)}";
            return redirectUrl;
        }

        /// <summary>
        /// Helper method to append an element to an array.
        /// </summary>
        private T[] Append<T>(T[] array, T element)
        {
            var list = new List<T>(array);
            list.Add(element);
            return list.ToArray();
        }

        /// <summary>
        /// Retrieves non-mutual followers from the Bluesky API.
        /// </summary>
        public async Task<IEnumerable<Subscriber>> GetNonMutualFollowersAsync()
        {
            // Get the access token from the current HTTP context.
            var accessToken = await _httpContextAccessor.HttpContext.GetTokenAsync("access_token");
            if (string.IsNullOrEmpty(accessToken))
            {
                throw new Exception("No access token available.");
            }

            // Set the Authorization header.
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            // Replace the URL with your actual endpoint.
            var response = await _httpClient.GetAsync("https://api.blueskyweb.xyz/your-endpoint-for-subscribers");
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync();
            var subscribers = JsonSerializer.Deserialize<List<Subscriber>>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });

            return subscribers ?? Enumerable.Empty<Subscriber>();
        }
    }
}
