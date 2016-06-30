using System.Net;
using System.Threading.Tasks;
using JE.IdentityServer.Security.Extensions;
using JE.IdentityServer.Security.OpenIdConnect;
using JE.IdentityServer.Security.Resources;
using Microsoft.Owin;

namespace JE.IdentityServer.Security.Recaptcha.Services
{
    public class HttpRecaptchaOkChallenge : IHttpRecaptchaChallenge
    {
        private readonly IRecaptchaPage _recaptchaPage;

        public HttpRecaptchaOkChallenge(IRecaptchaPage recaptchaPage)
        {
            _recaptchaPage = recaptchaPage;
        }

        public async Task ReturnResponse(IOwinContext context, IIdentityServerRecaptchaOptions options, IOpenIdConnectRequest openIdConnectRequest)
        {
            var identityServerChallengeResource = new IdentityServerBadRequestChallengeResource
            {
                Message = CreateResponseMessage(),
                ChallengeHtml = _recaptchaPage.CreateHtmlBody(openIdConnectRequest)
            };

            await context.ReturnResponse(HttpStatusCode.BadRequest, identityServerChallengeResource);
        }

        public async Task ReturnResponse(IOwinContext context, IIdentityServerRecaptchaOptions options)
        {
            var identityServerChallengeResource = new IdentityServerBadRequestChallengeResource
            {
                Message = CreateResponseMessage(),
                Challenge = _recaptchaPage.CreateHtmlBody()
            };

            await context.ReturnResponse(HttpStatusCode.BadRequest, identityServerChallengeResource);
        }

        private static string CreateResponseMessage()
        {
            return "Please complete the Recaptcha";
        }

        public void Dispose()
        {
            // NOOP
        }
    }
}