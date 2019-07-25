using System.Threading.Tasks;
using JE.IdentityServer.Security.OpenIdConnect;
using JE.IdentityServer.Security.Services;
using Microsoft.Owin;

namespace JE.IdentityServer.Security.Recaptcha.Pipeline
{
    public class ChallengeByIp : IdentityServerRecaptchaMiddlewareBase
    {
        public ChallengeByIp(OwinMiddleware next, IdentityServerRecaptchaOptions options) : base(next, options)
        {
        }

        public override async Task<PipelineState> DoInvoke(IOwinContext context, IOpenIdConnectRequest openIdConnectRequest, ILoginStatistics loginStatistics)
        {
            var numberOfFailedLogins = await loginStatistics.GetNumberOfFailedLoginsForIpAddress(openIdConnectRequest.GetRemoteIpAddress());

            if (numberOfFailedLogins < _options.NumberOfAllowedLoginFailuresPerIpAddress)
            {
                await loginStatistics.IncrementUnchallengedLoginsForUserAndIpAddress(openIdConnectRequest.GetUsername(),
                        openIdConnectRequest.GetRemoteIpAddress(), numberOfFailedLogins, _options.NumberOfAllowedLoginFailuresPerIpAddress);
                return PipelineState.Continue;
            }

            return PipelineState.Challenge;
        }
    }
}
