using JE.IdentityServer.Security.OpenIdConnect;

namespace JE.IdentityServer.Security.Recaptcha.Services
{
    public interface IRecaptchaPage
    {
        string CreateHtmlBody(IOpenIdConnectRequest openIdConnectRequest);

        string CreateHtmlBody();
    }
}