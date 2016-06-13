using JE.IdentityServer.Security.Resources;

namespace JE.IdentityServer.Security.Recaptcha.Services
{
    public interface IRecaptchaPage
    {
        string CreateHtmlBody(string languageCode, IDevice device);
    }
}