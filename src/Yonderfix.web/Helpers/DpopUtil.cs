namespace Yonderfix.web.Helpers
{
    using System;
    using System.IdentityModel.Tokens.Jwt;
    using System.Security.Claims;
    using System.Security.Cryptography;
    using Microsoft.IdentityModel.Tokens;
    using System.Text.Json;

    public static class DpopUtil
    {
        public static ECDsaSecurityKey GenerateDpopKeyPair()
        {
            var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            return new ECDsaSecurityKey(ecdsa) { KeyId = Guid.NewGuid().ToString("N") };
        }

        public static string ExportPrivateKey(ECDsaSecurityKey securityKey)
        {
            var parameters = securityKey.ECDsa.ExportParameters(true);
            return JsonSerializer.Serialize(new
            {
                kty = "EC",
                crv = "P-256", // Assuming nistP256
                d = Base64UrlEncoder.Encode(parameters.D),
                x = Base64UrlEncoder.Encode(parameters.Q.X),
                y = Base64UrlEncoder.Encode(parameters.Q.Y),
                kid = securityKey.KeyId
            });
        }

        public static ECDsaSecurityKey ImportPrivateKey(string privateKeyJwk)
        {
            var jwkParams = JsonSerializer.Deserialize<JsonElement>(privateKeyJwk);
            var parameters = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = Base64UrlEncoder.DecodeBytes(jwkParams.GetProperty("d").GetString()),
                Q = new ECPoint
                {
                    X = Base64UrlEncoder.DecodeBytes(jwkParams.GetProperty("x").GetString()),
                    Y = Base64UrlEncoder.DecodeBytes(jwkParams.GetProperty("y").GetString())
                }
            };
            var ecdsa = ECDsa.Create(parameters);
            return new ECDsaSecurityKey(ecdsa) { KeyId = jwkParams.GetProperty("kid").GetString() };
        }


        public static string GenerateDpopProof(string url, string httpMethod, ECDsaSecurityKey securityKey, string nonce = null)
        {
            var jwk = securityKey.ECDsa.ExportParameters(false); // Export public key
            var jwkThumbprint = Base64UrlEncoder.Encode(SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes(
                    $"{{\"crv\":\"{jwk.Curve.Oid.FriendlyName ?? "P-256"}\",\"kty\":\"EC\",\"x\":\"{Base64UrlEncoder.Encode(jwk.Q.X)}\",\"y\":\"{Base64UrlEncoder.Encode(jwk.Q.Y)}\"}}"
                )
            ));


            var now = DateTimeOffset.UtcNow;
            var claims = new List<Claim>
            {
                new Claim("htu", url),
                new Claim("htm", httpMethod),
                new Claim("jti", Guid.NewGuid().ToString("N")),
                new Claim("iat", now.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
            };

            if (!string.IsNullOrEmpty(nonce))
            {
                claims.Add(new Claim("nonce", nonce));
            }

            var handler = new JwtSecurityTokenHandler();
            var header = new JwtHeader(new SigningCredentials(securityKey, SecurityAlgorithms.EcdsaSha256));
            header.Add("jwk", JsonSerializer.Deserialize<object>(JsonSerializer.Serialize(new {
                kty = "EC",
                crv = "P-256", // Assuming nistP256 from GenerateDpopKeyPair
                x = Base64UrlEncoder.Encode(jwk.Q.X),
                y = Base64UrlEncoder.Encode(jwk.Q.Y),
                kid = securityKey.KeyId
            })));
            // The typ claim indicates that this JWT is a DPoP proof.
            header.Add("typ", "dpop+jwt");


            var payload = new JwtPayload(
                issuer: null, // Not needed for DPoP proof.
                audience: null, // Not needed for DPoP proof.
                claims: claims,
                notBefore: null,
                expires: now.AddSeconds(60).UtcDateTime,
                issuedAt: now.UtcDateTime
            );

            var token = new JwtSecurityToken(header, payload);
            return handler.WriteToken(token);
        }
    }
}
