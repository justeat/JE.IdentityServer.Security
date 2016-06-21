using System.Collections.Generic;
using System.Linq;
using System.Net;
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
            ExcludedSubnets = Enumerable.Empty<IPNetwork>();
            HttpRequestThrottledStatusCode = (HttpStatusCode) 429;
        }

        public string ProtectedPath { get; set; }

        public IEnumerable<string> ProtectedGrantTypes { get; set; }

        public Regex ExcludedUsernameExpression { get; set; }

        public Regex ExcludedTenantExpression { get; set; }

        public IEnumerable<IPNetwork> ExcludedSubnets { get; set; }

        public int NumberOfAllowedLoginFailures { get; set; }

        public HttpStatusCode HttpRequestThrottledStatusCode { get; set; }
    }
}