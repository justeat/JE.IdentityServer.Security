using System.Collections.Generic;
using System.Text.RegularExpressions;
using JE.IdentityServer.Security.Resources;

namespace JE.IdentityServer.Security.OpenIdConnect
{
    public interface IOpenIdConnectRequestOptions
    {
        string ProtectedPath { get; }

        IEnumerable<string> ProtectedGrantTypes { get; }

        IEnumerable<Regex> ExcludedUsernameExpressions { get; }

        IEnumerable<IPNetwork> ExcludedSubnets { get; set; }
    }
}