using System.Threading.Tasks;
using JE.IdentityServer.Security.Extensions;
using JE.IdentityServer.Security.OpenIdConnect;
using JE.IdentityServer.Security.Recaptcha.Services;
using JE.IdentityServer.Security.Services;
using Microsoft.Owin;

namespace JE.IdentityServer.Security.Recaptcha
{
    public class IdentityServerRecaptchaMiddleware : OwinMiddleware
    {
        private readonly IdentityServerRecaptchaOptions _options;

        public IdentityServerRecaptchaMiddleware(OwinMiddleware next, IdentityServerRecaptchaOptions options) 
            : base(next)
        {
            _options = options;
        }

        public override async Task Invoke(IOwinContext context)
        {
            var openIdConnectRequest = await context.ToOpenIdConnectRequest();
            var isExcludedFromRecaptcha = _options.IsExcluded(openIdConnectRequest);
            if (!_options.Matches(openIdConnectRequest) || isExcludedFromRecaptcha)
            {
                await Next.Invoke(context);
                return;
            }

            var loginStatistics = context.Get<ILoginStatistics>();
            if (await loginStatistics.GetNumberOfFailedLoginsForIpAddress(openIdConnectRequest.GetRemoteIpAddress()) <
                _options.NumberOfAllowedLoginFailuresPerIpAddress)
            {
                await Next.Invoke(context);
                return;
            }

            var recaptchaValidationService = context.Get<IRecaptchaValidationService>();
            var recaptchaChallengeResponse = openIdConnectRequest.GetRecaptchaChallengeResponse();
            if (!string.IsNullOrEmpty(recaptchaChallengeResponse))
            {
                var recaptchaVerificationResponse = await recaptchaValidationService.Validate(recaptchaChallengeResponse, _options);

                if (recaptchaVerificationResponse.Succeeded)
                {
                    await Next.Invoke(context);
                    return;
                }
            }

            await ChallengeWithRequestForRecaptcha(context, openIdConnectRequest);
        }

        private async Task ChallengeWithRequestForRecaptcha(IOwinContext context, IOpenIdConnectRequest openIdConnectRequest)
        {
            var loginStatistics = context.Get<ILoginStatistics>();

            await loginStatistics.IncrementFailedLoginsForUserAndIpAddress(openIdConnectRequest.GetUsername(),
                openIdConnectRequest.GetRemoteIpAddress());

            var httpChallenge = context.Get<IHttpRecaptchaChallenge>();
            await httpChallenge.ReturnResponse(context, _options, openIdConnectRequest);
        }
    }
}
