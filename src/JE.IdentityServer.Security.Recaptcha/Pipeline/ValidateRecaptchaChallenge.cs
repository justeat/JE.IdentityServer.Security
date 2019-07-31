using System.Threading.Tasks;
using JE.IdentityServer.Security.OpenIdConnect;
using JE.IdentityServer.Security.Services;
using Microsoft.Owin;
using JE.IdentityServer.Security.Extensions;
using JE.IdentityServer.Security.Recaptcha.Services;

namespace JE.IdentityServer.Security.Recaptcha.Pipeline
{
    public class ValidateRecaptchaChallenge : IdentityServerRecaptchaMiddlewareBase
    {
        public ValidateRecaptchaChallenge(OwinMiddleware next, IdentityServerRecaptchaOptions options) : base(next, options)
        {

        }

        protected override async Task<PipelineState> DoInvoke(IOwinContext context, IOpenIdConnectRequest openIdConnectRequest, ILoginStatistics loginStatistics)
        {
            var recaptchaValidationService = context.Get<IRecaptchaValidationService>();

            var recaptchaChallengeResponse = openIdConnectRequest.GetRecaptchaChallengeResponse();

            if (!string.IsNullOrEmpty(recaptchaChallengeResponse))
            {
                var recaptchaVerificationResponse = await recaptchaValidationService.Validate(recaptchaChallengeResponse, _options);

                if (recaptchaVerificationResponse.Succeeded)
                {
                    context.Set<IRecaptchaContext>(new RecaptchaContext(RecaptchaState.ChallengeSucceeded, recaptchaVerificationResponse.Hostname, recaptchaVerificationResponse.Timestamp));
                    return PipelineState.Continue;
                }
                else
                {
                    context.Set<IRecaptchaContext>(new RecaptchaContext(RecaptchaState.Failed, recaptchaVerificationResponse.Hostname, recaptchaVerificationResponse.Timestamp));
                    return PipelineState.Challenge;
                }
            }

            return PipelineState.Continue;
        }
    }
}
