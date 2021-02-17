using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net;
using JE.IdentityServer.Security.Extensions;
using JE.IdentityServer.Security.OpenIdConnect;
using JE.IdentityServer.Security.Resources;
using Microsoft.Owin;

namespace JE.IdentityServer.Security.Recaptcha.Resources
{
    internal class ValidationResourceBasedOpenIdConnectRequest : IOpenIdConnectRequest
    {
        private readonly RecaptchaValidationResource _recaptchaValidationResource;
        private readonly IOwinContext _owinContext;

        public ValidationResourceBasedOpenIdConnectRequest(RecaptchaValidationResource recaptchaValidationResource, IOwinContext owinContext)
        {
            _recaptchaValidationResource = recaptchaValidationResource;
            _owinContext = owinContext;
        }

        public string GetPath()
        {
            return _owinContext.Request.Path.Value;
        }

        public string GetUsername()
        {
            return _recaptchaValidationResource.Email;
        }

        public IPAddress GetRemoteIpAddress()
        {
            IPAddress remoteIpAddress;
            IPAddress.TryParse(_owinContext.GetRemoteClientIpAddress(), out remoteIpAddress);
            return remoteIpAddress;
        }

        public string GetLanguage()
        {
            return _recaptchaValidationResource.Language;
        }

        public string GetGrantType()
        {
            return string.Empty;
        }

        public string GetRecaptchaChallengeResponse()
        {
            return string.Empty;
        }

        public IDevice GetDevice()
        {
            return new Device(_recaptchaValidationResource.Device);
        }

        public string GetBasicAuthenticationHeaderValue()
        {
            return string.Empty;
        }

        public string GetTenant()
        {
            return _recaptchaValidationResource.Tenant;
        }

        public string GetOsVersion()
        {
            var osVersion = _recaptchaValidationResource.OsVersion;
            if (string.IsNullOrEmpty(osVersion))
            {
                osVersion = _recaptchaValidationResource.Sdk;
            }
            return osVersion;
        }

        public string GetUserAgent()
        {
            var userAgentHeaderValues = new string[] { };

            return _owinContext.Request.Headers.TryGetValue("User-Agent", out userAgentHeaderValues) ? userAgentHeaderValues.FirstOrDefault() : string.Empty;
        }

        public IReadOnlyDictionary<string, string> GetAcrValues()
        {
            return new ReadOnlyDictionary<string, string>(new Dictionary<string, string>());
        }
    }
}
