using System;
using System.Linq;

namespace JE.IdentityServer.Security.OpenIdConnect
{
    public static class OpenIdConnectRequestOptionsExtensions
    {
        public static bool Matches(this IOpenIdConnectRequestOptions openIdConnectRequestOptions, IOpenIdConnectRequest openIdConnectRequest)
        {
            var grantType = openIdConnectRequest.GetGrantType();
            var path = openIdConnectRequestOptions.ProtectedPath;
            if (string.IsNullOrEmpty(grantType) || string.IsNullOrEmpty(path))
            {
                return false;
            }

            return path.Equals(openIdConnectRequest.GetPath(), StringComparison.OrdinalIgnoreCase) && 
                   openIdConnectRequestOptions.ProtectedGrantTypes.Contains(grantType);
        }

        public static bool IsExcluded(this IOpenIdConnectRequestOptions options, IOpenIdConnectRequest openIdConnectRequest)
        {
            var username = openIdConnectRequest.GetUsername();
            if (!string.IsNullOrEmpty(username) && options.ExcludedUsernameExpression != null &&
                options.ExcludedUsernameExpression.IsMatch(username)) return true;

            var tenant = openIdConnectRequest.GetTenant();
            if (!string.IsNullOrEmpty(tenant) && options.ExcludedTenantExpression != null &&
                options.ExcludedTenantExpression.IsMatch(tenant)) return true;

            var osVersion = openIdConnectRequest.GetOsVersion();
            if (!string.IsNullOrEmpty(osVersion) && options.ExcludedOsVersionExpression != null &&
                options.ExcludedOsVersionExpression.IsMatch(osVersion)) return true;

            return options.ExcludedSubnets.Any(excludedSubnet => excludedSubnet.Contains(openIdConnectRequest.GetRemoteIpAddress()));
        }
    }
}