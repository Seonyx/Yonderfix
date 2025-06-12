using System;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using golf1052.atproto.net;
using golf1052.atproto.net.Models.AtProto.Server;

namespace Yonderfix.web.Services
{
    public class AtprotoService(HttpClient httpClient, AtProtoClient client)
    {
        private readonly AtProtoClient _client = client;
        private readonly HttpClient _httpClient = httpClient;

        /// <summary>
        /// Logs in the user by creating a new session with their handle and password.
        /// </summary>
        /// <remarks>
        /// This method uses direct password authentication which is generally not recommended for end-user-facing applications.
        /// Consider using the OAuth flow provided by BlueskyService for better security and user experience.
        /// </remarks>
        [Obsolete("Direct password login is not recommended for user authentication. Use OAuth flow via BlueskyService instead.")]
        public async Task<CreateSessionResponse> LoginAsync(string handle, string password)
        {
            // This method uses direct password authentication.
            // For end-user applications, OAuth (implemented in BlueskyService) is the preferred method.
            var request = new CreateSessionRequest
            {
                Identifier = handle,  // "Identifier" represents the user handle
                Password = password
            };

            var response = await _client.CreateSession(request);
            if (response == null || string.IsNullOrEmpty(response.AccessJwt))
            {
                throw new Exception("Login failed or returned invalid tokens.");
            }
            return response;
        }

        /// <summary>
        /// Refreshes the user’s session using the provided refresh token.
        /// Not implemented in the current version of the library.
        /// </summary>
        public Task<RefreshSessionResponse> RefreshTokenAsync(string refreshToken)
        {
            throw new NotImplementedException("Session refresh is not supported in the current version of the library.");
        }

        /// <summary>
        /// Resolves a Bluesky handle (e.g. "user.bsky.social") to a DID.
        /// Not implemented in the current version of the library.
        /// </summary>
        public Task<string> ResolveDidAsync(string handle)
        {
            throw new NotImplementedException("Handle resolution is not supported in the current version of the library.");
        }

        /// <summary>
        /// Retrieves the DID document and extracts the PDS hostname.
        /// Not implemented in the current version of the library.
        /// </summary>
        public Task<string> GetPdsHostnameAsync(string did)
        {
            throw new NotImplementedException("DID document retrieval is not supported in the current version of the library.");
        }
    }
}
