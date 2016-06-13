using System;
using System.Threading.Tasks;
using JE.IdentityServer.Security.OpenIdConnect;
using Microsoft.Owin;

namespace JE.IdentityServer.Security.Recaptcha.Services
{
    public interface IHttpRecaptchaChallenge : IDisposable
    {
        Task ReturnResponse(IOwinContext context, IIdentityServerRecaptchaOptions options, IOpenIdConnectRequest openIdConnectRequest);
    }
}