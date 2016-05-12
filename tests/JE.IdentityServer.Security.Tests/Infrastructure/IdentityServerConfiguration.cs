using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using IdentityServer3.Core;
using IdentityServer3.Core.Models;
using IdentityServer3.Core.Services.InMemory;

namespace JE.IdentityServer.Security.Tests.Infrastructure
{
    internal class IdentityServerConfiguration
    {
        public static X509Certificate2 Certificate
        {
            get
            {
                var assembly = typeof(IdentityServerConfiguration).Assembly;
                using (var stream = assembly.GetManifestResourceStream("JE.IdentityServer.Security.Tests.Infrastructure.idsrv3test.pfx"))
                {
                    return new X509Certificate2(ReadStream(stream), "idsrv3test");
                }
            }
        }

        private static byte[] ReadStream(Stream input)
        {
            var buffer = new byte[16 * 1024];
            using (var memoryStream = new MemoryStream())
            {
                int read;
                while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                {
                    memoryStream.Write(buffer, 0, read);
                }
                return memoryStream.ToArray();
            }
        }

        public static IEnumerable<Client> Clients
        {
            get
            {
                yield return new Client
                {
                    Enabled = true,
                    ClientName = "Web Applications Native Login",
                    ClientId = "web_native",
                    Flow = Flows.ResourceOwner,
                    ClientSecrets = new List<Secret>
                    {
                        new Secret("cb0da8d4-2243-4f96-9a96-d01d1c301320".Sha256())
                    },
                    AllowedScopes = Scopes.Select(s => s.Name).ToList(),
                    RequireConsent = false,
                    RefreshTokenUsage = TokenUsage.OneTimeOnly,
                    RefreshTokenExpiration = TokenExpiration.Sliding,
                    UpdateAccessTokenClaimsOnRefresh = true,
                    AccessTokenLifetime = 2000000,
                    AbsoluteRefreshTokenLifetime = 2000000,
                    SlidingRefreshTokenLifetime = 2000000
                };
            }
        }

        public static IEnumerable<Scope> Scopes
        {
            get
            {
                var scopes = new List<Scope>();
                scopes.AddRange(StandardScopes.AllAlwaysInclude);
                scopes.Add(StandardScopes.OfflineAccess);
                scopes.Add(new Scope
                {
                    Enabled = true,
                    Name = "mobile_scope",
                    DisplayName = "Mobile Scope",
                    Type = ScopeType.Resource,
                    IncludeAllClaimsForUser = true,
                    Claims = new List<ScopeClaim>
                    {
                        new ScopeClaim(Constants.ClaimTypes.Subject, true),
                        new ScopeClaim(Constants.ClaimTypes.Name, true)
                    }
                });
                return scopes;
            }
        }

        public static List<InMemoryUser> Users => new List<InMemoryUser>
        {
            new InMemoryUser
            {
                Username = "jeuser",
                Password = "Passw0rd",
                Subject = "101",

                Claims = new[]
                {
                    new Claim("email", "user@just-eat.com"),
                    new Claim("name", "JUST EAT user")
                }
            }
        };
    }
}