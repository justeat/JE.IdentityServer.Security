using System;
using JE.IdentityServer.Security.Throttling;
using Owin;

namespace JE.IdentityServer.Security.Ravelin
{
    public static class IdentityServerRavelinRealtimeProtectionAppBuilderExtensions
    {
        public static IAppBuilder UseThrottlingForAuthenticationRequests(this IAppBuilder app, RavelinRealtimeProtectionOptions options)
        {
            if (app == null) throw new ArgumentNullException(nameof(app));

            app.Use<RavelinRealtimeProtection>(options);

            return app;
        }
    }
}
