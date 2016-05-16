using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace JE.IdentityServer.Security.OpenIdConnect
{
    public interface IOpenIdConnectRequestOptions
    {
        string ProtectedPath { get; }

        IEnumerable<string> ProtectedGrantTypes { get; }

        IEnumerable<Regex> ExcludedUsernameExpressions { get; }

        int NumberOfAllowedLoginFailures { get; }
    }
}