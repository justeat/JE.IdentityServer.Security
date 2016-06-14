using JE.IdentityServer.Security.OpenIdConnect;
using JE.IdentityServer.Security.Resources;

namespace JE.IdentityServer.Security.Recaptcha.Services
{
    public interface IRecaptchaPage
    {
        string CreateHtmlBody(IOpenIdConnectRequest openIdConnectRequest);
    }
}