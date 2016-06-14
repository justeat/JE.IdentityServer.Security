using System;
using System.Linq;
using System.Net.Http.Headers;
using System.Text;
using JE.IdentityServer.Security.OpenIdConnect;

namespace JE.IdentityServer.Security.Recaptcha.Services
{
    internal static class IdentityServerRecaptchaOptionsExtenstions
    {
        public static bool SupportsPartialRecaptcha(this IIdentityServerRecaptchaOptions openIdConnectRequestOptions, IOpenIdConnectRequest openIdConnectRequest)
        {
            var basicAuthenticationHeaders = openIdConnectRequestOptions.WebClients.Select(client => Convert.ToBase64String(Encoding.UTF8.GetBytes($"{client.ClientId}:{client.Secret}")))
                .Select(authorizationValue => new AuthenticationHeaderValue("Basic", authorizationValue));
            return basicAuthenticationHeaders
                .Any(authenticationHeaderValue => authenticationHeaderValue.ToString() == openIdConnectRequest.GetBasicAuthenticationHeaderValue());
        }
    }
}
