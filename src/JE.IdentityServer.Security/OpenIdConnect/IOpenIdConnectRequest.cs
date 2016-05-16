using System.Net;

namespace JE.IdentityServer.Security.OpenIdConnect
{
    public interface IOpenIdConnectRequest
    {
        bool Matches(IOpenIdConnectRequestOptions openIdConnectRequestOptions);

        bool IsExcluded(IOpenIdConnectRequestOptions options);

        string GetUsername();

        IPAddress GetRemoteIpAddress();
    }
}