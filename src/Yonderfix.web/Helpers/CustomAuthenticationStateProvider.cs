using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;
using Duende.IdentityModel.Client;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity.Data;
using golf1052.atproto.net;

namespace Yonderfix.web.Services
{
    public class CustomAuthenticationStateProvider : AuthenticationStateProvider
    {
        private readonly AtProtoClient _atProtoClient;
        private readonly AtprotoService _atprotoService;
        private string _accessToken;
        private string _refreshToken;
        private readonly ClaimsPrincipal _anonymous = new ClaimsPrincipal(new ClaimsIdentity());

        public CustomAuthenticationStateProvider(AtProtoClient atProtoClient, AtprotoService atprotoService)
        {
            _atProtoClient = atProtoClient;
            _atprotoService = atprotoService;
        }

        public override Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            if (string.IsNullOrEmpty(_accessToken))
            {
                return Task.FromResult(new AuthenticationState(_anonymous));
            }
            var claims = ParseClaimsFromJwt(_accessToken);
            var identity = new ClaimsIdentity(claims, "jwt");
            var user = new ClaimsPrincipal(identity);
            return Task.FromResult(new AuthenticationState(user));
        }

        /// <summary>
        /// Marks the user as authenticated by storing the tokens and notifying subscribers.
        /// </summary>
        public Task MarkUserAsAuthenticated(string accessToken, string refreshToken)
        {
            _accessToken = accessToken;
            _refreshToken = refreshToken;
            var claims = ParseClaimsFromJwt(_accessToken);
            var identity = new ClaimsIdentity(claims, "jwt");
            var user = new ClaimsPrincipal(identity);
            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(user)));
            return Task.CompletedTask;
        }

        /// <summary>
        /// Clears stored tokens and marks the user as logged out.
        /// </summary>
        public void MarkUserAsLoggedOut()
        {
            _accessToken = null;
            _refreshToken = null;
            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(_anonymous)));
        }

        /// <summary>
        /// Refreshes the access token using the stored refresh token.
        /// </summary>
        public async Task RefreshTokenAsync()
        {
            if (string.IsNullOrEmpty(_refreshToken))
                throw new Exception("No refresh token available.");

            var response = await _atprotoService.RefreshTokenAsync(_refreshToken);
            _accessToken = response.AccessJwt;
            _refreshToken = response.RefreshJwt;
            var claims = ParseClaimsFromJwt(_accessToken);
            var identity = new ClaimsIdentity(claims, "jwt");
            var user = new ClaimsPrincipal(identity);
            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(user)));
        }

        /// <summary>
        /// A simple JWT parser that extracts claims from the token payload.
        /// </summary>
        private IEnumerable<Claim> ParseClaimsFromJwt(string jwt)
        {
            var claims = new List<Claim>();
            try
            {
                var payload = jwt.Split('.')[1];
                var jsonBytes = ParseBase64WithoutPadding(payload);
                var keyValuePairs = JsonSerializer.Deserialize<Dictionary<string, object>>(jsonBytes);
                if (keyValuePairs != null)
                {
                    claims.AddRange(keyValuePairs.Select(kvp => new Claim(kvp.Key, kvp.Value.ToString())));
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error parsing JWT: {ex.Message}");
            }
            return claims;
        }

        private byte[] ParseBase64WithoutPadding(string base64)
        {
            switch (base64.Length % 4)
            {
                case 2: base64 += "=="; break;
                case 3: base64 += "="; break;
            }
            return Convert.FromBase64String(base64);
        }
    }
}
