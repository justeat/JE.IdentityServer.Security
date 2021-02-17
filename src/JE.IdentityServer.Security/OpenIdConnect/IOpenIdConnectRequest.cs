using System.Collections.Generic;
using System.Net;
using JE.IdentityServer.Security.Resources;

namespace JE.IdentityServer.Security.OpenIdConnect
{
    public interface IOpenIdConnectRequest
    {
        string GetPath();

        string GetUsername();

        IPAddress GetRemoteIpAddress();

        string GetLanguage();

        string GetGrantType();

        string GetRecaptchaChallengeResponse();

        IDevice GetDevice();

        string GetBasicAuthenticationHeaderValue();

        string GetTenant();

        string GetOsVersion();

        string GetUserAgent();

        IReadOnlyDictionary<string, string> GetAcrValues();
    }
}
