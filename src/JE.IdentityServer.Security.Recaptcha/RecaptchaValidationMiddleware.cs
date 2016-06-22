using System.Net;
using System.Threading.Tasks;
using JE.IdentityServer.Security.Extensions;
using JE.IdentityServer.Security.OpenIdConnect;
using JE.IdentityServer.Security.Recaptcha.Resources;
using JE.IdentityServer.Security.Recaptcha.Services;
using JE.IdentityServer.Security.Services;
using Microsoft.Owin;

namespace JE.IdentityServer.Security.Recaptcha
{
    public class RecaptchaValidationMiddleware : OwinMiddleware
    {
        private readonly RecaptchaValidationOptions _options;

        public RecaptchaValidationMiddleware(OwinMiddleware next, RecaptchaValidationOptions options) 
            : base(next)
        {
            _options = options;
        }

        public override async Task Invoke(IOwinContext context)
        {
            var recaptchaValidationResource = context.ReadRequestBodyAsync<RecaptchaValidationResource>();
            var openIdConnectRequest = recaptchaValidationResource == null ? null :
                                           new ValidationResourceBasedOpenIdConnectRequest(recaptchaValidationResource, context);
            var isExcludedFromRecaptcha = _options.IsExcluded(context, openIdConnectRequest);
            if (!_options.Matches(context) || isExcludedFromRecaptcha)
            {
                await Next.Invoke(context);
                return;
            }

            var loginStatistics = context.Get<ILoginStatistics>();
            var remoteClientIpAddress = context.GetRemoteClientIpAddress();
            IPAddress ipAaddress;
            if (!IPAddress.TryParse(remoteClientIpAddress, out ipAaddress))
            {
                await Next.Invoke(context);
                return;
            }
            
            var challengeForAllLogins = await ShouldChallengeForAllLogins(context);
            if (!challengeForAllLogins && 
                await loginStatistics.GetNumberOfFailedLoginsForIpAddress(ipAaddress) < _options.NumberOfAllowedLoginFailuresPerIpAddress)
            {
                await Next.Invoke(context);
                return;
            }
            
            await ChallengeWithRequestForRecaptcha(context, openIdConnectRequest);
        }

        private static async Task<bool> ShouldChallengeForAllLogins(IOwinContext context)
        {
            var platformSecurity = context.Get<IPlatformSecurity>();
            return platformSecurity != null && await platformSecurity.ShieldsAreUp();
        }

        private async Task ChallengeWithRequestForRecaptcha(IOwinContext context, IOpenIdConnectRequest openIdConnectRequest)
        {
            var httpChallenge = context.Get<IHttpRecaptchaChallenge>();
            if (openIdConnectRequest == null)
            {
                await httpChallenge.ReturnResponse(context, _options);
                return;
            }

            await httpChallenge.ReturnResponse(context, _options, openIdConnectRequest);
        }
    }
}
