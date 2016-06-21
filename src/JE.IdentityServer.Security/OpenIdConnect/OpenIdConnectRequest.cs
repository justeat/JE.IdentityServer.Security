using System.Net;
using JE.IdentityServer.Security.Extensions;
using JE.IdentityServer.Security.Resources;
using Microsoft.Owin;

namespace JE.IdentityServer.Security.OpenIdConnect
{
    public class OpenIdConnectRequest : IOpenIdConnectRequest
    {
        private const string AcrValuesFormKey = "acr_values";
        private const string RecaptchaAnswerHeaderKey = "x-recaptcha-answer";
        private const string GrantTypeFormKey = "grant_type";

        private readonly IPAddress _remoteIpAddress;
        private readonly string _path;
        private readonly IHeaderDictionary _headers;
        private readonly IFormCollection _form;

        public OpenIdConnectRequest(IPAddress remoteIpAddress, string path, IHeaderDictionary headers, IFormCollection form)
        {
            _remoteIpAddress = remoteIpAddress;
            _path = path;
            _headers = headers;
            _form = form;
        }

        public string GetUsername()
        {
            return _form.Get("username");
        }

        public string GetPath()
        {
            return _path;
        }

        public IPAddress GetRemoteIpAddress()
        {
            return _remoteIpAddress;
        }

        public string GetLanguage()
        {
            return _form.Get(AcrValuesFormKey).ToKnownAcrValues().Language;
        }

        public string GetGrantType()
        {
            return _form.Get(GrantTypeFormKey);
        }

        public string GetRecaptchaChallengeResponse()
        {
            var recaptchaValue = _headers.Get(RecaptchaAnswerHeaderKey);
            return !string.IsNullOrEmpty(recaptchaValue)
                ? recaptchaValue.ToStringFromBase64String()
                : _form.Get(AcrValuesFormKey)
                    .ToKnownAcrValues().RecaptchaResponse;
        }

        public IDevice GetDevice()
        {
            return _form.Get(AcrValuesFormKey).ToKnownAcrValues().Device;
        }

        public string GetTenant()
        {
            return _form.Get(AcrValuesFormKey).ToKnownAcrValues().Tenant;
        }

        public string GetBasicAuthenticationHeaderValue()
        {
            return _headers.Get("Authorization");
        }
    }
}