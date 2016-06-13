using System.Threading.Tasks;
using JE.IdentityServer.Security.Extensions;
using JE.IdentityServer.Security.OpenIdConnect;
using JE.IdentityServer.Security.Resources;
using JE.IdentityServer.Security.Services;
using Microsoft.Owin;

namespace JE.IdentityServer.Security.Throttling
{
    public class IdentityServerThrottlingMiddleware : OwinMiddleware
    {
        private readonly IdentityServerThrottlingOptions _options;

        public IdentityServerThrottlingMiddleware(
            OwinMiddleware next, 
            IdentityServerThrottlingOptions options) : base(next)
        {
            _options = options;
        }

        public override async Task Invoke(IOwinContext context)
        {
            var openIdConnectRequest = await context.ToOpenIdConnectRequest();
            var isExcludedFromThrottling = _options.IsExcluded(openIdConnectRequest);
            if (!_options.Matches(openIdConnectRequest) || isExcludedFromThrottling)
            {
                if (isExcludedFromThrottling)
                {
                    await SetLoginStatusForExcludedUser(context, openIdConnectRequest);
                }

                await Next.Invoke(context);
                return;
            }

            await InvokeCore(context, openIdConnectRequest);
        }

        private async Task InvokeCore(IOwinContext context, IOpenIdConnectRequest openIdConnectRequest)
        {
            var username = openIdConnectRequest.GetUsername();
            var loginStatistics = context.Get<ILoginStatistics>();
            if (loginStatistics != null)
            {
                var numberOfFailedLogins = await loginStatistics.GetNumberOfFailedLoginsForUser(username);
                if (numberOfFailedLogins >= _options.NumberOfAllowedLoginFailures)
                {
                    await context.ReturnResponse(429, new IdentityServerErrorResource
                    {
                        Message = "Too many connections"
                    });

                    return;
                }
            }

            await Next.Invoke(context);

            await SetLoginStatusForUser(context, openIdConnectRequest);
        }

        private static async Task SetLoginStatusForUser(IOwinContext context, IOpenIdConnectRequest openIdConnectRequest)
        {
            var loginStatistics = context.Get<ILoginStatistics>();
            if (loginStatistics == null)
            {
                return;
            }

            if (IsSuccessStatusCode(context.Response.StatusCode))
            {
                await loginStatistics.IncrementSuccessfulLoginsForUsernameAndIpAddress(openIdConnectRequest.GetUsername(), openIdConnectRequest.GetRemoteIpAddress());
            }
            else
            {
                await loginStatistics.IncrementFailedLoginsForUserAndIpAddress(openIdConnectRequest.GetUsername(), openIdConnectRequest.GetRemoteIpAddress());
            }
        }

        private static async Task SetLoginStatusForExcludedUser(IOwinContext context, IOpenIdConnectRequest openIdConnectRequest)
        {
            var loginStatistics = context.Get<ILoginStatistics>();
            if (loginStatistics == null)
            {
                return;
            }

            await loginStatistics.IncrementAttemptedLoginsForExcludedUsernameAndIpAddress(openIdConnectRequest.GetUsername(), openIdConnectRequest.GetRemoteIpAddress());
        }

        private static bool IsSuccessStatusCode(int statusCode)
        {
            return (statusCode >= 200) && (statusCode <= 299);
        }
    }
}
