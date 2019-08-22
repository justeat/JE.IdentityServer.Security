using System.Threading.Tasks;
using JE.IdentityServer.Security.Extensions;
using JE.IdentityServer.Security.OpenIdConnect;
using JE.IdentityServer.Security.Recaptcha.Services;
using JE.IdentityServer.Security.Services;
using Microsoft.Owin;

namespace JE.IdentityServer.Security.Recaptcha.Pipeline
{

    public abstract class IdentityServerRecaptchaMiddlewareBase : OwinMiddleware
    {
        protected readonly IdentityServerRecaptchaOptions Options;

        protected IdentityServerRecaptchaMiddlewareBase(OwinMiddleware next, IdentityServerRecaptchaOptions options)
            : base(next)
        {
            Options = options;
        }

        public override async Task Invoke(IOwinContext context)
        {
            var openIdConnectRequest = await context.ToOpenIdConnectRequest();
            var isExcludedFromRecaptcha = Options.IsExcluded(openIdConnectRequest);

            var loginStatistics = context.Get<ILoginStatistics>();
            var recaptchaContext = context.Get<IRecaptchaContext>();
            var recaptchaTracker = context.Get<IRecaptchaTracker>();

            if (recaptchaContext != null)
            {
                if (!recaptchaTracker.IsCompleted)
                {
                    var recaptchaMonitor = context.Get<IRecaptchaMonitor>();

                    recaptchaMonitor?.ChallengeCompleted(openIdConnectRequest.ToRecaptchaUserContext(), recaptchaContext.ToRecaptchaResponseContext());

                    recaptchaTracker.IsCompleted = true;
                }

                switch (recaptchaContext.State)
                {
                    case RecaptchaState.Failed:
                        {
                            await Challenge(context, openIdConnectRequest, loginStatistics);
                            return;
                        }
                    case RecaptchaState.ChallengeSucceeded:
                        await context.CleanupAcrValues();
                        await Next.Invoke(context);
                        return;
                }
            }

            if (Options.Matches(openIdConnectRequest) && !isExcludedFromRecaptcha)
            {
                var result = await DoInvoke(context, openIdConnectRequest, loginStatistics);

                switch (result)
                {
                    case PipelineState.Challenge:
                        {
                            var numberOfFailedLogins = await loginStatistics.GetNumberOfFailedLoginsForIpAddress(openIdConnectRequest.GetRemoteIpAddress());

                            await ChallengeWithRequestForRecaptcha(context, openIdConnectRequest, numberOfFailedLogins);

                            return;
                        }
                    case PipelineState.Continue:
                        break;
                }
            }

            await Next.Invoke(context);
        }

        private async Task Challenge(IOwinContext context, IOpenIdConnectRequest openIdConnectRequest, ILoginStatistics loginStatistics)
        {
            var numberOfFailedLogins = await loginStatistics.GetNumberOfFailedLoginsForIpAddress(openIdConnectRequest.GetRemoteIpAddress());

            await ChallengeWithRequestForRecaptcha(context, openIdConnectRequest, numberOfFailedLogins);
        }

        private async Task ChallengeWithRequestForRecaptcha(IOwinContext context, IOpenIdConnectRequest openIdConnectRequest, int numberOfFailedLogins)
        {
            var loginStatistics = context.Get<ILoginStatistics>();
            var recaptchaMonitor = context.Get<IRecaptchaMonitor>();

            await loginStatistics.IncrementFailedLoginsForUserAndIpAddress(openIdConnectRequest.GetUsername(),
                openIdConnectRequest.GetRemoteIpAddress());

            await loginStatistics.IncrementChallengedLoginsForUserAndIpAddress(openIdConnectRequest.GetUsername(),
                openIdConnectRequest.GetRemoteIpAddress(), numberOfFailedLogins, Options.NumberOfAllowedLoginFailuresPerIpAddress);

            recaptchaMonitor?.ChallengeIssued(openIdConnectRequest.ToRecaptchaUserContext());

            var httpChallenge = context.Get<IHttpRecaptchaChallenge>();
            await httpChallenge.ReturnResponse(context, Options, openIdConnectRequest);
        }

        protected abstract Task<PipelineState> DoInvoke(IOwinContext context, IOpenIdConnectRequest openIdConnectRequest, ILoginStatistics loginStatistics);
    }
}
