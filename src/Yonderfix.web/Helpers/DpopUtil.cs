namespace Yonderfix.web.Helpers
{
    using System;
    using System.IdentityModel.Tokens.Jwt;
    using System.Security.Claims;
    using System.Security.Cryptography;
    using Microsoft.IdentityModel.Tokens;

    public static class DpopUtil
    {
        // For demonstration, generate a new ECDsa key pair on the fly.
        // In production, generate and store a per-session key pair.
        public static string GenerateDpopProof(string url, string httpMethod)
        {
            using (var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                // Create a security key from the ECDsa instance.
                var securityKey = new ECDsaSecurityKey(ecdsa) { KeyId = Guid.NewGuid().ToString("N") };

                var now = DateTimeOffset.UtcNow;
                var claims = new[]
                {
                new Claim("htu", url),
                new Claim("htm", httpMethod),
                new Claim("jti", Guid.NewGuid().ToString("N")),
                new Claim("iat", now.ToUnixTimeSeconds().ToString())
            };

                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Issuer = null, // Not needed for DPoP proof.
                    Subject = new ClaimsIdentity(claims),
                    Expires = now.AddSeconds(60).UtcDateTime,
                    SigningCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.EcdsaSha256)
                };

                var handler = new JwtSecurityTokenHandler();
                var token = handler.CreateJwtSecurityToken(tokenDescriptor);
                return handler.WriteToken(token);
            }
        }
    }
}
