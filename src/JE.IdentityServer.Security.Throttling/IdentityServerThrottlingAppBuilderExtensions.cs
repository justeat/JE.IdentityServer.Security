using System;
using Owin;

namespace JE.IdentityServer.Security.Throttling
{
    public static class IdentityServerThrottlingAppBuilderExtensions
    {
        public static IAppBuilder UseThrottlingForAuthenticationRequests(this IAppBuilder app, IdentityServerThrottlingOptions options)
        {
            if (app == null) throw new ArgumentNullException(nameof(app));
            if (options == null) throw new ArgumentNullException(nameof(options));

            app.Use<IdentityServerThrottlingMiddleware>(options);

            return app;
        }
    }
}