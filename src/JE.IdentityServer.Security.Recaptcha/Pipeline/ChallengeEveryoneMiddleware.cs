using System.Threading.Tasks;
using JE.IdentityServer.Security.Extensions;
using JE.IdentityServer.Security.OpenIdConnect;
using JE.IdentityServer.Security.Services;
using Microsoft.Owin;

namespace JE.IdentityServer.Security.Recaptcha.Pipeline
{
    public class ChallengeEveryoneMiddleware : IdentityServerRecaptchaMiddlewareBase
    {
        public ChallengeEveryoneMiddleware(OwinMiddleware next, IdentityServerRecaptchaOptions options) : base(next, options)
        {
        }

        protected override async Task<PipelineState> DoInvoke(IOwinContext context, IOpenIdConnectRequest openIdConnectRequest, ILoginStatistics loginStatistics)
        {
            var challengeForAllLogins = await ShouldChallengeForAllLogins(context);
            if (challengeForAllLogins)
            {
                return PipelineState.Challenge;
            }

            return PipelineState.Continue;

        }

        private static async Task<bool> ShouldChallengeForAllLogins(IOwinContext context)
        {
            var platformSecurity = context.Get<IPlatformSecurity>();
            return platformSecurity != null && await platformSecurity.ShieldsAreUp();
        }
    }
}
