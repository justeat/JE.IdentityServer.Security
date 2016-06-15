using System.Net;
using System.Threading.Tasks;
using JE.IdentityServer.Security.Extensions;
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
            var isExcludedFromRecaptcha = _options.IsExcluded(context);
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

            var platformSecurity = context.Get<IPlatformSecurity>();
            var challengeForAllLogins = platformSecurity != null && await platformSecurity.ShieldsAreUp();
            if (!challengeForAllLogins && 
                await loginStatistics.GetNumberOfFailedLoginsForIpAddress(ipAaddress) < _options.NumberOfAllowedLoginFailuresPerIpAddress)
            {
                await Next.Invoke(context);
                return;
            }
            
            await ChallengeWithRequestForRecaptcha(context);
        }

        private async Task ChallengeWithRequestForRecaptcha(IOwinContext context)
        {
            var httpChallenge = context.Get<IHttpRecaptchaChallenge>();
            await httpChallenge.ReturnResponse(context, _options);
        }
    }
}
