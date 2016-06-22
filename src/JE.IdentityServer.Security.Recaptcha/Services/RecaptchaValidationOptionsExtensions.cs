using System;
using System.Linq;
using System.Net;
using JE.IdentityServer.Security.Extensions;
using JE.IdentityServer.Security.OpenIdConnect;
using Microsoft.Owin;

namespace JE.IdentityServer.Security.Recaptcha.Services
{
    public static class RecaptchaValidationOptionsExtensions
    {
        public static bool Matches(this RecaptchaValidationOptions recaptchaValidationOptions, IOwinContext owinContext)
        {
            var path = recaptchaValidationOptions.ProtectedPath;
            return !string.IsNullOrEmpty(path) && path.Equals(owinContext.ResourcePath(), StringComparison.OrdinalIgnoreCase);
        }

        public static bool IsExcluded(this RecaptchaValidationOptions recaptchaValidationOptions, IOwinContext owinContext, IOpenIdConnectRequest openIdConnectRequest)
        {
            var subnetExcluded = recaptchaValidationOptions.ExcludedSubnets.Any(excludedSubnet =>
            {
                var remoteClientIpAddress = owinContext.GetRemoteClientIpAddress();
                IPAddress ipAaddress;
                return IPAddress.TryParse(remoteClientIpAddress, out ipAaddress) && excludedSubnet.Contains(ipAaddress);
            });

            if (subnetExcluded) return true;

            if (openIdConnectRequest == null) return false;

            var username = openIdConnectRequest.GetUsername();
            if (!string.IsNullOrEmpty(username) && recaptchaValidationOptions.ExcludedUsernameExpression != null &&
                recaptchaValidationOptions.ExcludedUsernameExpression.IsMatch(username)) return true;

            var tenant = openIdConnectRequest.GetTenant();
            if (!string.IsNullOrEmpty(tenant) && recaptchaValidationOptions.ExcludedTenantExpression != null &&
                recaptchaValidationOptions.ExcludedTenantExpression.IsMatch(tenant)) return true;

            var osVersion = openIdConnectRequest.GetOsVersion();
            if (!string.IsNullOrEmpty(osVersion) && recaptchaValidationOptions.ExcludedOsVersionExpression != null &&
                recaptchaValidationOptions.ExcludedOsVersionExpression.IsMatch(osVersion)) return true;

            return false;
        }
    }
}
