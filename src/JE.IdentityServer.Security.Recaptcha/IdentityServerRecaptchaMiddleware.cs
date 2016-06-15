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
            var numberOfFailedLogins = await loginStatistics.GetNumberOfFailedLoginsForIpAddress(openIdConnectRequest.GetRemoteIpAddress());

            var platformSecurity = context.Get<IPlatformSecurity>();
            var challengeForAllLogins = platformSecurity != null && await platformSecurity.ShieldsAreUp();
            if (!challengeForAllLogins && numberOfFailedLogins < _options.NumberOfAllowedLoginFailuresPerIpAddress)
            {
                await loginStatistics.IncrementUnchallengedLoginsForUserAndIpAddress(openIdConnectRequest.GetUsername(),
                        openIdConnectRequest.GetRemoteIpAddress(), numberOfFailedLogins, _options.NumberOfAllowedLoginFailuresPerIpAddress);
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

            await ChallengeWithRequestForRecaptcha(context, openIdConnectRequest, numberOfFailedLogins);
        }

        private async Task ChallengeWithRequestForRecaptcha(IOwinContext context, IOpenIdConnectRequest openIdConnectRequest, int numberOfFailedLogins)
        {
            var loginStatistics = context.Get<ILoginStatistics>();

            await loginStatistics.IncrementFailedLoginsForUserAndIpAddress(openIdConnectRequest.GetUsername(),
                openIdConnectRequest.GetRemoteIpAddress());

            await loginStatistics.IncrementChallengedLoginsForUserAndIpAddress(openIdConnectRequest.GetUsername(),
                openIdConnectRequest.GetRemoteIpAddress(), numberOfFailedLogins, _options.NumberOfAllowedLoginFailuresPerIpAddress);

            var httpChallenge = context.Get<IHttpRecaptchaChallenge>();
            await httpChallenge.ReturnResponse(context, _options, openIdConnectRequest);
        }
    }
}
