using System.Threading.Tasks;
using JE.IdentityServer.Security.Extensions;
using JE.IdentityServer.Security.OpenIdConnect;
using JE.IdentityServer.Security.Recaptcha.Services;
using JE.IdentityServer.Security.Services;
using Microsoft.Owin;
using NLog;
using NLog.StructuredLogging.Json;

namespace JE.IdentityServer.Security.Recaptcha.Pipeline
{

    public abstract class IdentityServerRecaptchaMiddlewareBase : OwinMiddleware
    {
        protected readonly IdentityServerRecaptchaOptions _options;
        protected readonly ILogger _logger;

        protected IdentityServerRecaptchaMiddlewareBase(OwinMiddleware next, IdentityServerRecaptchaOptions options)
            : base(next)
        {
            _options = options;
            _logger = LogManager.GetCurrentClassLogger();
        }

        public override async Task Invoke(IOwinContext context)
        {
            var openIdConnectRequest = await context.ToOpenIdConnectRequest();
            var isExcludedFromRecaptcha = _options.IsExcluded(openIdConnectRequest);

            var loginStatistics = context.Get<ILoginStatistics>();
            var recaptchaContext = context.Get<IRecaptchaContext>();

            if (recaptchaContext != null)
            {
                _logger.ExtendedInfo("Recaptcha completed", new { username = openIdConnectRequest.GetUsername(), ipAddress = openIdConnectRequest.GetRemoteIpAddress(), RecaptchaState = recaptchaContext.State, RecaptchaHostname = recaptchaContext.Hostname });

                var recaptchaMonitor = context.Get<IRecaptchaMonitor>();

                recaptchaMonitor?.ChallengeCompleted(openIdConnectRequest.ToRecaptchaUserContext(), recaptchaContext.ToRecaptchaResponseContext());

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

            if (_options.Matches(openIdConnectRequest) && !isExcludedFromRecaptcha)
            {
                var result = await DoInvoke(context, openIdConnectRequest, loginStatistics);

                switch (result)
                {
                    case PipelineState.Challenge:
                        {
                            var numberOfFailedLogins = await loginStatistics.GetNumberOfFailedLoginsForIpAddress(openIdConnectRequest.GetRemoteIpAddress());

                            await ChallengeWithRequestForRecaptcha(context, openIdConnectRequest, numberOfFailedLogins);
                            _logger.ExtendedInfo("Issuing Recaptcha Challenge", new { username = openIdConnectRequest.GetUsername(), ipAddress = openIdConnectRequest.GetRemoteIpAddress(), userAgent = openIdConnectRequest.GetUserAgent(), RecaptchaState = recaptchaContext?.State, numberOfFailedLogins });

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
                openIdConnectRequest.GetRemoteIpAddress(), numberOfFailedLogins, _options.NumberOfAllowedLoginFailuresPerIpAddress);

            recaptchaMonitor?.ChallengeIssued(openIdConnectRequest.ToRecaptchaUserContext());

            var httpChallenge = context.Get<IHttpRecaptchaChallenge>();
            await httpChallenge.ReturnResponse(context, _options, openIdConnectRequest);
        }

        protected abstract Task<PipelineState> DoInvoke(IOwinContext context, IOpenIdConnectRequest openIdConnectRequest, ILoginStatistics loginStatistics);
    }
}
