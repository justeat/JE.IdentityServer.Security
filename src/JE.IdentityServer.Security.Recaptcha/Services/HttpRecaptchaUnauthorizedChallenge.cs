using System.Net;
using System.Threading.Tasks;
using JE.IdentityServer.Security.Extensions;
using JE.IdentityServer.Security.OpenIdConnect;
using JE.IdentityServer.Security.Resources;
using Microsoft.Owin;

namespace JE.IdentityServer.Security.Recaptcha.Services
{
    public class HttpRecaptchaUnauthorizedChallenge : IHttpRecaptchaChallenge
    {
        private readonly IRecaptchaPage _recaptchaPage;

        public HttpRecaptchaUnauthorizedChallenge(IRecaptchaPage recaptchaPage)
        {
            _recaptchaPage = recaptchaPage;
        }

        public async Task ReturnResponse(IOwinContext context, IIdentityServerRecaptchaOptions options, IOpenIdConnectRequest openIdConnectRequest)
        {
            await context.ReturnResponse(HttpStatusCode.Unauthorized,
                new IdentityServerUnauthorizedChallengeResource
                {
                    ChallengeHtml = _recaptchaPage.CreateHtmlBody(openIdConnectRequest),
                    LinkToChallenge = "/recaptcha.aspx",
                    Description = CreateResponseMessage()
                }, $@"recaptcha url=""{options.LinkToChallenge}""");
        }

        private static string CreateResponseMessage()
        {
            return "Please respond to the reCaptcha challenge by rendering the html to the user and harvesting the g-recaptcha-response field value. See https://developers.google.com/recaptcha/docs/verify. Rerun your original request as before, but add the x-recaptcha-answer header to it.";
        }

        public void Dispose()
        {
            // NOOP
        }
    }
}