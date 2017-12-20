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
        public string ProtectedPath { get; set; }

        public IEnumerable<string> ProtectedGrantTypes { get; set; } = Enumerable.Empty<string>();

        public virtual Regex ExcludedUsernameExpression { get; set; }

        public virtual Regex ExcludedTenantExpression { get; set; }

        public virtual Regex ExcludedOsVersionExpression { set; get; }

        public virtual Regex ExcludedDeviceExpression { get; set; }

        public virtual IEnumerable<IPNetwork> ExcludedSubnets { get; set; } = Enumerable.Empty<IPNetwork>();

        public virtual int NumberOfAllowedLoginFailures { get; set; }

        public virtual HttpStatusCode HttpRequestThrottledStatusCode { get; set; } = (HttpStatusCode)429;
    }
}
