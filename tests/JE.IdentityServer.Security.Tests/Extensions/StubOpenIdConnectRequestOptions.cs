using System.Collections.Generic;
using System.Text.RegularExpressions;
using JE.IdentityServer.Security.OpenIdConnect;
using JE.IdentityServer.Security.Resources;

namespace JE.IdentityServer.Security.Tests.Extensions
{
    internal class StubOpenIdConnectRequestOptions : IOpenIdConnectRequestOptions
    {
        public StubOpenIdConnectRequestOptions()
        {
            ProtectedPath = "identity/connect/token";
            ProtectedGrantTypes = new[] { "password" };
            ExcludedUsernameExpression = new Regex("example\\.com$");
            ExcludedTenantExpression = new Regex("es");
            ExcludedOsVersionExpression = new Regex("5.0");
            NumberOfAllowedLoginFailures = 10;
            ExcludedSubnets = new[] {new IPNetwork("192.168.100.0/24")};
        }

        public string ProtectedPath { get; }

        public IEnumerable<string> ProtectedGrantTypes { get; }

        public Regex ExcludedUsernameExpression { get; }

        public Regex ExcludedTenantExpression { get; }

        public Regex ExcludedOsVersionExpression { get; }

        public Regex ExcludedDeviceExpression { get; set; }

        public IEnumerable<IPNetwork> ExcludedSubnets { get; }

        public int NumberOfAllowedLoginFailures { get; }
    }
}