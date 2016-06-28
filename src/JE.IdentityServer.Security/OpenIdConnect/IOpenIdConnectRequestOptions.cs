using System.Collections.Generic;
using System.Text.RegularExpressions;
using JE.IdentityServer.Security.Resources;

namespace JE.IdentityServer.Security.OpenIdConnect
{
    public interface IOpenIdConnectRequestOptions
    {
        string ProtectedPath { get; }

        IEnumerable<string> ProtectedGrantTypes { get; }

        IEnumerable<IPNetwork> ExcludedSubnets { get; }

        Regex ExcludedUsernameExpression { get; }

        Regex ExcludedTenantExpression { get; }

        Regex ExcludedOsVersionExpression { get; }

        Regex ExcludedDeviceExpression { get; set; }
    }
}