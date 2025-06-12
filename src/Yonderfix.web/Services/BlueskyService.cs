using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using System.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens; // For ECDsaSecurityKey
using Yonderfix.web.Helpers;         // For PkceUtil and DpopUtil
using Yonderfix.web.Models;           // Ensure Subscriber is defined here

namespace Yonderfix.web.Services
{
    #region API Response Models
    public class ApiActorProfile
    {
        [JsonPropertyName("did")]
        public string Did { get; set; }

        [JsonPropertyName("handle")]
        public string Handle { get; set; }

        [JsonPropertyName("displayName")]
        public string DisplayName { get; set; }

        [JsonPropertyName("avatar")]
        public string Avatar { get; set; }

        [JsonPropertyName("viewer")]
        public ApiActorViewerState Viewer { get; set; }
    }

    public class ApiActorViewerState
    {
        [JsonPropertyName("following")]
        public string? Following { get; set; } // URI if authenticated user is following this actor

        [JsonPropertyName("followedBy")]
        public string? FollowedBy { get; set; } // URI if this actor is following the authenticated user
    }

    public class ApiGetFollowsResponse
    {
        [JsonPropertyName("follows")]
        public List<ApiActorProfile> Follows { get; set; } = new List<ApiActorProfile>();

        [JsonPropertyName("subject")]
        public ApiActorProfile Subject { get; set; } // The user whose list this is

        [JsonPropertyName("cursor")]
        public string? Cursor { get; set; }
    }

    public class ApiGetFollowersResponse
    {
        [JsonPropertyName("followers")]
        public List<ApiActorProfile> Followers { get; set; } = new List<ApiActorProfile>();

        [JsonPropertyName("subject")]
        public ApiActorProfile Subject { get; set; }

        [JsonPropertyName("cursor")]
        public string? Cursor { get; set; }
    }
    #endregion

    public class TokenResponse
    {
        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; }

        [JsonPropertyName("refresh_token")]
        public string RefreshToken { get; set; }

        [JsonPropertyName("scope")]
        public string Scope { get; set; }

        [JsonPropertyName("sub")]
        public string UserDid { get; set; } // User's DID

        [JsonPropertyName("expires_in")]
        public int ExpiresIn { get; set; }
    }

    public class BlueskyService
    {
        private readonly HttpClient _httpClient;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IConfiguration _configuration;
        private readonly ILogger<BlueskyService> _logger;
        private readonly string _blueskyApiBaseUrl;


        // Configuration values for OAuth flow.
        private readonly string _clientId;
        private readonly string _redirectUri;
        private readonly string _parEndpoint;
        private readonly string _authEndpoint;
        private readonly string _tokenEndpoint;

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
            _tokenEndpoint = _configuration["Authentication:Bluesky:TokenEndpoint"];
            _blueskyApiBaseUrl = _configuration["Authentication:Bluesky:ApiBaseUrl"] ?? "https://bsky.social"; // Default if not configured
        }

        private ECDsaSecurityKey GetSessionDpopKey()
        {
            var dpopPrivateKeyJwk = _httpContextAccessor.HttpContext.Session.GetString("session_dpop_private_key");
            if (string.IsNullOrEmpty(dpopPrivateKeyJwk))
            {
                _logger.LogError("Session DPoP private key not found. This key should be set after successful login.");
                throw new Exception("Session DPoP private key not found.");
            }
            return DpopUtil.ImportPrivateKey(dpopPrivateKeyJwk);
        }

        private ECDsaSecurityKey GetOAuthFlowDpopKey(string state) // Specifically for retrieving key during OAuth flow using state
        {
            var dpopPrivateKeyJwk = _httpContextAccessor.HttpContext.Session.GetString($"oauth_dpop_private_key_{state}");
            if (string.IsNullOrEmpty(dpopPrivateKeyJwk))
            {
                _logger.LogError("OAuth flow DPoP private key not found in session for state: {state}", state);
                throw new Exception($"OAuth flow DPoP private key not found for state {state}.");
            }
            return DpopUtil.ImportPrivateKey(dpopPrivateKeyJwk);
        }

        private string GetUserDidFromSession()
        {
            var userDid = _httpContextAccessor.HttpContext.Session.GetString("user_did");
            if (string.IsNullOrEmpty(userDid))
            {
                _logger.LogError("User DID not found in session.");
                throw new Exception("User DID not found in session. Please login again.");
            }
            return userDid;
        }

        private string GetAccessTokenFromSession()
        {
            var accessToken = _httpContextAccessor.HttpContext.Session.GetString("access_token");
            if (string.IsNullOrEmpty(accessToken))
            {
                _logger.LogWarning("Access token not found in session.");
                throw new Exception("Access token not found in session. Please login again.");
            }
            return accessToken;
        }


        private async Task<T> SendAuthenticatedRequestAsync<T>(
            HttpMethod method,
            string endpointPath,
            HttpContent? requestBody = null,
            Dictionary<string, string>? queryParams = null)
        {
            var accessToken = GetAccessTokenFromSession();
            var dpopKey = GetSessionDpopKey(); // Use the general session DPoP key for API calls

            string requestUrl = $"{_blueskyApiBaseUrl}{endpointPath}";
            if (queryParams != null)
            {
                var uriBuilder = new UriBuilder(requestUrl);
                var httpValueCollection = HttpUtility.ParseQueryString(uriBuilder.Query);
                foreach (var param in queryParams)
                {
                    httpValueCollection[param.Key] = param.Value;
                }
                uriBuilder.Query = httpValueCollection.ToString();
                requestUrl = uriBuilder.ToString();
            }

            HttpResponseMessage response = null;
            string? dpopNonce = null;
            int attempts = 0;

            while (attempts < 2) // Max 2 attempts (initial + 1 retry with nonce)
            {
                attempts++;
                var request = new HttpRequestMessage(method, requestUrl);
                if (requestBody != null)
                {
                    // Clone content for retries if it's a stream content that can't be re-read
                    if (requestBody is StringContent || requestBody is FormUrlEncodedContent)
                    {
                        request.Content = requestBody;
                    }
                    else // For StreamContent or other non-rewindable content, it needs careful handling for retries.
                    {
                        // This simple example assumes content is rewindable or re-creatable.
                        // For production, ensure requestBody can be sent multiple times.
                        // A common pattern is to read StreamContent into a ByteArrayContent for retries.
                        if (attempts > 1 && requestBody is StreamContent) throw new InvalidOperationException("StreamContent cannot be automatically retried without buffering.");
                        request.Content = requestBody;
                    }
                }

                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                string dpopProof = DpopUtil.GenerateDpopProof(requestUrl, method.Method, dpopKey, dpopNonce);
                request.Headers.Add("DPoP", dpopProof);

                _logger.LogInformation("Attempt {Attempt}: Sending {Method} request to {Url}. DPoP Nonce used: {Nonce}", attempts, method.Method, requestUrl, dpopNonce ?? "null");

                response = await _httpClient.SendAsync(request);

                if (response.IsSuccessStatusCode)
                {
                    _logger.LogInformation("{Method} request to {Url} successful on attempt {Attempt}", method.Method, requestUrl, attempts);
                    var responseBody = await response.Content.ReadAsStringAsync();
                    return JsonSerializer.Deserialize<T>(responseBody, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                }

                if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized && response.Headers.TryGetValues("DPoP-Nonce", out var nonceValues))
                {
                    dpopNonce = nonceValues.FirstOrDefault();
                    if (!string.IsNullOrEmpty(dpopNonce))
                    {
                        _logger.LogInformation("Received DPoP-Nonce: {Nonce} for {Url}. Retrying...", dpopNonce, requestUrl);
                        // Dispose of the previous request content if it's disposable and not null.
                        // Note: The original requestBody is passed in, so it should be managed by the caller for disposal if needed after the SendAuthenticatedRequestAsync call completes.
                        // Here, we are concerned about the HttpContent on the HttpRequestMessage.
                        if (request.Content != null)
                        {
                           // If we cloned it: request.Content.Dispose();
                           // If it's the original, don't dispose here as it might be needed for another attempt.
                        }
                        continue; // Retry the loop
                    }
                }

                var errorContent = await response.Content.ReadAsStringAsync();
                _logger.LogError("{Method} request to {Url} failed on attempt {Attempt}: {StatusCode} {ReasonPhrase}. Body: {ErrorBody}", method.Method, requestUrl, attempts, response.StatusCode, response.ReasonPhrase, errorContent);
                response.EnsureSuccessStatusCode(); // This will throw for non-success codes not handled above
            }
            // Should not be reached if EnsureSuccessStatusCode() is called or if successful.
            throw new Exception("Request failed after multiple attempts.");
        }


        public async Task<string> StartAuthorizationFlowAsync(string loginHint = null)
        {
            _logger.LogInformation("Starting OAuth authorization flow. Login hint: {LoginHint}", loginHint ?? "N/A");
            try
            {
                string state = Guid.NewGuid().ToString("N");
                string codeVerifier = PkceUtil.GenerateCodeVerifier();
                string codeChallenge = PkceUtil.GenerateCodeChallenge(codeVerifier);

                var dpopKeyPair = DpopUtil.GenerateDpopKeyPair();
                string dpopPrivateKeyJwk = DpopUtil.ExportPrivateKey(dpopKeyPair);

                _httpContextAccessor.HttpContext.Session.SetString($"oauth_state_{state}", state);
                _httpContextAccessor.HttpContext.Session.SetString($"oauth_code_verifier_{state}", codeVerifier);
                _httpContextAccessor.HttpContext.Session.SetString($"oauth_dpop_private_key_{state}", dpopPrivateKeyJwk); // Stored with state
                _logger.LogInformation("OAuth state, code_verifier, and DPoP private key stored in session for state {State}.", state);

                var parParameters = new List<KeyValuePair<string, string>>
                {
                new KeyValuePair<string, string>("client_id", _clientId),
                new KeyValuePair<string, string>("redirect_uri", _redirectUri),
                new KeyValuePair<string, string>("response_type", "code"),
                new KeyValuePair<string, string>("scope", "atproto transition:generic"),
                new KeyValuePair<string, string>("state", state),
                new KeyValuePair<string, string>("code_challenge", codeChallenge),
                new KeyValuePair<string, string>("code_challenge_method", "S256")
            };
            if (!string.IsNullOrEmpty(loginHint)) parParameters.Add(new KeyValuePair<string, string>("login_hint", loginHint));

            var parContent = new FormUrlEncodedContent(parParameters);
            string parDpopProof = DpopUtil.GenerateDpopProof(_parEndpoint, "POST", dpopKeyPair);

            var parRequest = new HttpRequestMessage(HttpMethod.Post, _parEndpoint) { Content = parContent };
            parRequest.Headers.Add("DPoP", parDpopProof);

                var parResponse = await _httpClient.SendAsync(parRequest);

                if (!parResponse.IsSuccessStatusCode)
                {
                    var errorBody = await parResponse.Content.ReadAsStringAsync();
                    _logger.LogError("PAR request to {ParEndpoint} failed with status {StatusCode}. Response: {ErrorBody}", _parEndpoint, parResponse.StatusCode, errorBody);
                    throw new HttpRequestException($"Pushed Authorization Request failed. Status: {parResponse.StatusCode}, Body: {errorBody}");
                }
                _logger.LogInformation("PAR request to {ParEndpoint} successful.", _parEndpoint);

                var jsonParResponse = await parResponse.Content.ReadAsStringAsync();
                using var doc = JsonDocument.Parse(jsonParResponse);
                if (!doc.RootElement.TryGetProperty("request_uri", out var requestUriElement) || string.IsNullOrEmpty(requestUriElement.GetString()))
                {
                    _logger.LogError("PAR response from {ParEndpoint} did not contain a valid 'request_uri'. Response: {JsonResponse}", _parEndpoint, jsonParResponse);
                    throw new Exception("PAR response did not contain a request_uri.");
                }
                string requestUri = requestUriElement.GetString();
                string authorizationUrl = $"{_authEndpoint}?client_id={Uri.EscapeDataString(_clientId)}&request_uri={Uri.EscapeDataString(requestUri)}";
                _logger.LogInformation("Successfully generated authorization URL for state {State}.", state);
                return authorizationUrl;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in StartAuthorizationFlowAsync for login hint {LoginHint}.", loginHint ?? "N/A");
                throw; // Re-throw the exception to be handled by the caller
            }
        }

        public async Task<TokenResponse> ExchangeCodeForTokensAsync(string code, string stateFromCallback)
        {
            _logger.LogInformation("Attempting to exchange authorization code for tokens. State: {State}", stateFromCallback);
            HttpResponseMessage response = null;
            try
            {
                var storedCodeVerifier = _httpContextAccessor.HttpContext.Session.GetString($"oauth_code_verifier_{stateFromCallback}");
                var oauthFlowDpopKey = GetOAuthFlowDpopKey(stateFromCallback); // Key associated with this specific OAuth flow

                if (string.IsNullOrEmpty(storedCodeVerifier))
                {
                    _logger.LogError("Code verifier not found in session for state: {State}. Aborting token exchange.", stateFromCallback);
                    throw new Exception("Session data missing for token exchange (code_verifier).");
                }
                _logger.LogDebug("Retrieved code_verifier and OAuth DPoP key for state {State}.", stateFromCallback);

                var tokenRequestBody = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("grant_type", "authorization_code"),
                new KeyValuePair<string, string>("code", code),
                new KeyValuePair<string, string>("redirect_uri", _redirectUri),
                new KeyValuePair<string, string>("client_id", _clientId),
                new KeyValuePair<string, string>("code_verifier", storedCodeVerifier)
            });

            // Use SendAuthenticatedRequestAsync for the token exchange POST request.
            // However, SendAuthenticatedRequestAsync expects Bearer token auth, not form-urlencoded body for client auth.
            // So, we'll do this one manually as before, but using the retrieved dpopKey.
            HttpResponseMessage response = null;
            string dpopNonce = null;
            int attempts = 0;

            while (attempts < 2)
            {
                attempts++;
                // Re-create content for each attempt as it might be disposed
                var currentTokenRequestBody = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("grant_type", "authorization_code"),
                    new KeyValuePair<string, string>("code", code),
                    new KeyValuePair<string, string>("redirect_uri", _redirectUri),
                    new KeyValuePair<string, string>("client_id", _clientId),
                    new KeyValuePair<string, string>("code_verifier", storedCodeVerifier)
                });

                var request = new HttpRequestMessage(HttpMethod.Post, _tokenEndpoint) { Content = currentTokenRequestBody };
                    string dpopProof = DpopUtil.GenerateDpopProof(_tokenEndpoint, "POST", oauthFlowDpopKey, dpopNonce);
                    request.Headers.Add("DPoP", dpopProof);

                    _logger.LogInformation("Attempt {Attempt}: Sending token request to {TokenEndpoint}. DPoP Nonce used: {Nonce}", attempts, _tokenEndpoint, dpopNonce ?? "null");
                    response = await _httpClient.SendAsync(request);

                    if (response.IsSuccessStatusCode)
                    {
                        _logger.LogInformation("Token exchange request to {TokenEndpoint} successful on attempt {Attempt}.", _tokenEndpoint, attempts);
                        break;
                    }
                    if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized && response.Headers.TryGetValues("DPoP-Nonce", out var nonceValues))
                    {
                        dpopNonce = nonceValues.FirstOrDefault();
                        if (!string.IsNullOrEmpty(dpopNonce))
                        {
                            _logger.LogInformation("Received DPoP-Nonce from {TokenEndpoint}: {Nonce}. Retrying...", _tokenEndpoint, dpopNonce);
                            continue;
                        }
                        _logger.LogWarning("Received DPoP-Nonce header from {TokenEndpoint}, but nonce value was empty. Failing.", _tokenEndpoint);
                    }
                    var errorContent = await response.Content.ReadAsStringAsync(); // Read error content before EnsureSuccessStatusCode
                    _logger.LogError("Token exchange request to {TokenEndpoint} failed on attempt {Attempt} with status {StatusCode}. Response: {ErrorBody}", _tokenEndpoint, attempts, response.StatusCode, errorContent);
                    response.EnsureSuccessStatusCode(); // This will throw
                }

                var jsonResponse = await response.Content.ReadAsStringAsync();
                var tokenData = JsonSerializer.Deserialize<TokenResponse>(jsonResponse, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

                if (tokenData == null || string.IsNullOrEmpty(tokenData.AccessToken) || string.IsNullOrEmpty(tokenData.UserDid))
                {
                    _logger.LogError("Failed to deserialize token response, or access_token/sub (UserDID) is missing. Response: {JsonResponse}", jsonResponse);
                    throw new Exception("Failed to obtain valid access token or UserDID from token response.");
                }

                _logger.LogInformation("Successfully exchanged code for tokens for UserDID: {UserDid}. State: {State}", tokenData.UserDid, stateFromCallback);

                var dpopPrivateKeyJwkForSession = DpopUtil.ExportPrivateKey(oauthFlowDpopKey);
                if (!string.IsNullOrEmpty(dpopPrivateKeyJwkForSession))
                {
                    _httpContextAccessor.HttpContext.Session.SetString("session_dpop_private_key", dpopPrivateKeyJwkForSession);
                    _logger.LogInformation("Session DPoP key stored for UserDID: {UserDid} from state {State}.", tokenData.UserDid, stateFromCallback);
                }
                else
                {
                    _logger.LogWarning("Failed to export DPoP private key for session storage for UserDID: {UserDid}. DPoP for API calls may fail.", tokenData.UserDid);
                }

                _httpContextAccessor.HttpContext.Session.Remove($"oauth_state_{stateFromCallback}");
                _httpContextAccessor.HttpContext.Session.Remove($"oauth_code_verifier_{stateFromCallback}");
                _httpContextAccessor.HttpContext.Session.Remove($"oauth_dpop_private_key_{stateFromCallback}");
                _logger.LogInformation("Cleaned up OAuth-specific session state for state {State}.", stateFromCallback);

                return tokenData;
            }
            catch (JsonException jsonEx)
            {
                var responseContent = response != null ? await response.Content.ReadAsStringAsync() : "N/A";
                _logger.LogError(jsonEx, "JSON deserialization error during token exchange for state {State}. Response content: {ResponseContent}", stateFromCallback, responseContent);
                throw new Exception("Error processing token server response.", jsonEx);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in ExchangeCodeForTokensAsync for state {State}.", stateFromCallback);
                throw;
            }
        }

        public async Task<(List<Subscriber> Subscribers, string? Cursor)> GetMyFollowersWithFollowBackStatusAsync(int limit = 30, string? cursor = null)
        {
            var authenticatedUserDid = GetUserDidFromSession(); // This already logs if DID is not found
            _logger.LogInformation("Attempting to fetch followers for authenticated user {UserDID}. Limit: {Limit}, Cursor: {Cursor}", authenticatedUserDid, limit, cursor);

            try
            {
                var queryParams = new Dictionary<string, string>
                {
                    { "actor", authenticatedUserDid },
                    { "limit", limit.ToString() }
                };
                if (!string.IsNullOrEmpty(cursor))
                {
                    queryParams["cursor"] = cursor;
                }

                var responseData = await SendAuthenticatedRequestAsync<ApiGetFollowersResponse>(
                    HttpMethod.Get,
                    "/xrpc/app.bsky.graph.getFollowers",
                    queryParams: queryParams);

                var subscribers = new List<Subscriber>();
                if (responseData?.Followers != null)
                {
                    foreach (var follower in responseData.Followers)
                    {
                        subscribers.Add(new Subscriber
                        {
                            Did = follower.Did,
                            Handle = follower.Handle,
                            DisplayName = follower.DisplayName ?? string.Empty,
                            ProfilePictureUrl = follower.Avatar ?? string.Empty,
                            IsFollowedByMe = !string.IsNullOrEmpty(follower.Viewer?.Following),
                            FollowsMeBack = !string.IsNullOrEmpty(follower.Viewer?.Following),
                            MyFollowRecordUri = follower.Viewer?.Following
                        });
                    }
                    _logger.LogInformation("Successfully fetched {FollowerCount} followers for user {UserDID}. Next cursor: {NextCursor}", subscribers.Count, authenticatedUserDid, responseData.Cursor ?? "N/A");
                }
                else
                {
                    _logger.LogWarning("Received null or empty followers list from API for user {UserDID}.", authenticatedUserDid);
                }
                return (subscribers, responseData?.Cursor);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error fetching followers for user {UserDID}. Limit: {Limit}, Cursor: {Cursor}", authenticatedUserDid, limit, cursor);
                throw;
            }
        }

        public async Task UnfollowUserAsync(string userToUnfollowDid, string followRecordUri)
        {
            var authenticatedUserDid = GetUserDidFromSession();
            _logger.LogInformation("User {AuthenticatedUserDid} attempting to unfollow DID {UserToUnfollowDid} using record URI {FollowRecordUri}", authenticatedUserDid, userToUnfollowDid, followRecordUri);

            if (string.IsNullOrEmpty(followRecordUri))
            {
                _logger.LogError("Follow record URI is required to unfollow user {UserToUnfollowDid}.", userToUnfollowDid);
                throw new ArgumentException("Follow record URI cannot be null or empty.", nameof(followRecordUri));
            }

            var rkey = string.Empty;
            try
            {
                var uriParts = followRecordUri.Split('/');
                if (uriParts.Length == 0 || string.IsNullOrEmpty(uriParts.Last()))
                {
                    _logger.LogError("Invalid follow record URI format: {FollowRecordUri}. Could not extract rkey.", followRecordUri);
                    throw new ArgumentException("Invalid follow record URI format. Cannot extract rkey.", nameof(followRecordUri));
                }
                rkey = uriParts.Last();
                _logger.LogDebug("Extracted rkey {Rkey} from URI {FollowRecordUri} for unfollow operation.", rkey, followRecordUri);

                var requestBody = new
                {
                    repo = authenticatedUserDid,
                    collection = "app.bsky.graph.follow",
                    rkey = rkey
                };

                var jsonRequestBody = JsonSerializer.Serialize(requestBody);
                var content = new StringContent(jsonRequestBody, Encoding.UTF8, "application/json");

                await SendAuthenticatedRequestAsync<object>(
                    HttpMethod.Post,
                    "/xrpc/com.atproto.repo.deleteRecord",
                    requestBody: content);

                _logger.LogInformation("Successfully sent unfollow request for DID {UserToUnfollowDid} (rkey: {Rkey}) by user {AuthenticatedUserDid}.", userToUnfollowDid, rkey, authenticatedUserDid);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during unfollow operation for DID {UserToUnfollowDid} (rkey: {Rkey}) by user {AuthenticatedUserDid}.", userToUnfollowDid, rkey, authenticatedUserDid);
                throw;
            }
        }
    }
}
            // Code for GetMyFollowersWithFollowBackStatusAsync and UnfollowUserAsync remains here, unchanged by this diff snippet
            // ...
        }
    }
}
