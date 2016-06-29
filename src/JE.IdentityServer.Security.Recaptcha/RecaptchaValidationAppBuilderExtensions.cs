using System;
using System.Net;
using System.Threading.Tasks;
using JE.IdentityServer.Security.Recaptcha.Services;
using JE.IdentityServer.Security.Resolver;
using Owin;

namespace JE.IdentityServer.Security.Recaptcha
{
    public static class RecaptchaValidationAppBuilderExtensions
    {
        /// <summary>
        ///     Serves the URL 'options.ProtectedPath', but will never yield a Recaptcha challenge
        /// </summary>
        public static IAppBuilder UseRecaptchaValidationDisabledEndpoint(this IAppBuilder app,
            RecaptchaValidationOptions options)
        {
            return app.UseRecaptchaValidationEndpointCore(options, false);
        }

        /// <summary>
        ///     Serves the URL 'options.ProtectedPath' and will yield a Recaptcha challenge if shields are up
        /// </summary>
        public static IAppBuilder UseRecaptchaValidationEnabledEndpoint(this IAppBuilder app,
            RecaptchaValidationOptions options)
        {
            return app.UseRecaptchaValidationEndpointCore(options, true);
        }

        private static IAppBuilder UseRecaptchaValidationEndpointCore(this IAppBuilder app,
            RecaptchaValidationOptions options, bool enableRecaptcha)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            app.Map(options.ProtectedPath, challenge =>
            {
                challenge.UseRequestedChallengeType(options);
                if (enableRecaptcha)
                {
                    challenge.Use<RecaptchaValidationMiddleware>(options);
                }
                challenge.Run(ctx =>
                {
                    ctx.Response.StatusCode = (int) HttpStatusCode.NoContent;
                    return Task.FromResult(0);
                });
            });

            return app;
        }

        private static void UseRequestedChallengeType(this IAppBuilder app, IIdentityServerRecaptchaOptions options)
        {
            if (options.HttpChallengeStatusCode == HttpStatusCode.Unauthorized)
            {
                app.UsePerOwinContext<IHttpRecaptchaChallenge>(
                    () => new HttpRecaptchaUnauthorizedChallenge(new RecaptchaPage(options)));
            }
            else
            {
                app.UsePerOwinContext<IHttpRecaptchaChallenge>(
                    () => new HttpRecaptchaBadRequestChallenge(new RecaptchaPage(options)));
            }
        }
    }
}