using System;
using System.Net;
using JE.IdentityServer.Security.Recaptcha.Services;
using JE.IdentityServer.Security.Resolver;
using Owin;
using JE.IdentityServer.Security.Recaptcha.Pipeline;

namespace JE.IdentityServer.Security.Recaptcha
{
    public static class IdentityServerRecaptchaAppBuilderExtensions
    {
        public static IRecaptchaMiddlewareBuilder UseRecaptchaForAuthenticationRequests(this IAppBuilder app,
            IdentityServerRecaptchaOptions options,
            Func<IRecaptchaValidationService> recaptchaValidationService)
        {
            if (app == null) throw new ArgumentNullException(nameof(app));
            if (options == null) throw new ArgumentNullException(nameof(options));

            if (recaptchaValidationService == null)
            {
                recaptchaValidationService = () => new DefaultRecaptchaValidationService();
            }

            app.UsePerOwinContext<IRecaptchaTracker>(() => new RecaptchaTracker());

            app.UseRequestedChallengeType(options);

            app.UsePerOwinContext(recaptchaValidationService);

            var recaptchaMiddlewareBuilder = new RecaptchaMiddlewareBuilder(app, options);

            recaptchaMiddlewareBuilder.UseRecaptchaMiddleware<ValidateRecaptchaChallenge>();
            recaptchaMiddlewareBuilder.UseRecaptchaMiddleware<ChallengeEveryoneMiddleware>();
            recaptchaMiddlewareBuilder.UseRecaptchaMiddleware<ChallengeByIp>();

            return recaptchaMiddlewareBuilder;
        }

        public static IRecaptchaMiddlewareBuilder UseRecaptchaMiddleware<TMiddleware>(this IRecaptchaMiddlewareBuilder app) where TMiddleware : IdentityServerRecaptchaMiddlewareBase
        {
            app.Use<TMiddleware>(app.Options);

            return app;
        }

        public static IRecaptchaMiddlewareBuilder UseRecaptchaForAuthenticationRequests(this IAppBuilder app,
            IdentityServerRecaptchaOptions options)
        {
            return app.UseRecaptchaForAuthenticationRequests(options,
                () => new DefaultRecaptchaValidationService());
        }

        private static void UseRequestedChallengeType(this IAppBuilder app, IIdentityServerRecaptchaOptions options)
        {
            switch (options.HttpChallengeStatusCode)
            {
                case HttpStatusCode.OK:
                    app.UsePerOwinContext<IHttpRecaptchaChallenge>(
                        () => new HttpRecaptchaOkChallenge(new RecaptchaPage(options)));
                    break;
                case HttpStatusCode.Unauthorized:
                    app.UsePerOwinContext<IHttpRecaptchaChallenge>(
                        () => new HttpRecaptchaUnauthorizedChallenge(new RecaptchaPage(options)));
                    break;
                default:
                    app.UsePerOwinContext<IHttpRecaptchaChallenge>(
                        () => new HttpRecaptchaBadRequestChallenge(new RecaptchaPage(options)));
                    break;
            }
        }
    }
}
