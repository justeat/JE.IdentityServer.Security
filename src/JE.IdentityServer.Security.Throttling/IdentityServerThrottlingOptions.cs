using System.Collections.Generic;
using System.Text.RegularExpressions;
using JE.IdentityServer.Security.OpenIdConnect;

namespace JE.IdentityServer.Security.Throttling
{
    public class IdentityServerThrottlingOptions : IOpenIdConnectRequestOptions
    {
        public IdentityServerThrottlingOptions()
        {
            ProtectedGrantTypes = new List<string>();
            ExcludedUsernameExpressions = new List<Regex>();
        }

        public string ProtectedPath { get; set; }

        public IEnumerable<string> ProtectedGrantTypes { get; set; }

        public IEnumerable<Regex> ExcludedUsernameExpressions { get; set; }

        public int NumberOfAllowedLoginFailures { get; set; }
    }
}