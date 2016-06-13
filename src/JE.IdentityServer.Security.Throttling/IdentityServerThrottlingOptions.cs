using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using JE.IdentityServer.Security.OpenIdConnect;
using JE.IdentityServer.Security.Resources;

namespace JE.IdentityServer.Security.Throttling
{
    public class IdentityServerThrottlingOptions : IOpenIdConnectRequestOptions
    {
        public IdentityServerThrottlingOptions()
        {
            ProtectedGrantTypes = Enumerable.Empty<string>();
            ExcludedUsernameExpressions = Enumerable.Empty<Regex>();
            ExcludedSubnets = Enumerable.Empty<IPNetwork>();
        }

        public string ProtectedPath { get; set; }

        public IEnumerable<string> ProtectedGrantTypes { get; set; }

        public IEnumerable<Regex> ExcludedUsernameExpressions { get; set; }

        public IEnumerable<IPNetwork> ExcludedSubnets { get; set; }

        public int NumberOfAllowedLoginFailures { get; set; }
    }
}