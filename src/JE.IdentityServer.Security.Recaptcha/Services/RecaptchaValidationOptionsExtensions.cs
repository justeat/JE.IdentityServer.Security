using System;
using System.Linq;
using System.Net;
using JE.IdentityServer.Security.Extensions;
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

        public static bool IsExcluded(this RecaptchaValidationOptions recaptchaValidationOptions, IOwinContext owinContext)
        {
            return recaptchaValidationOptions.ExcludedSubnets.Any(excludedSubnet =>
            {
                var remoteClientIpAddress = owinContext.GetRemoteClientIpAddress();
                IPAddress ipAaddress;
                return IPAddress.TryParse(remoteClientIpAddress, out ipAaddress) && excludedSubnet.Contains(ipAaddress);
            });
        }
    }
}
