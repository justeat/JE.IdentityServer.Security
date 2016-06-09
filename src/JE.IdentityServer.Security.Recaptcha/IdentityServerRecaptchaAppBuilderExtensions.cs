using System;
using System.Net;
using JE.IdentityServer.Security.Recaptcha.Services;
using JE.IdentityServer.Security.Resolver;
using Owin;

namespace JE.IdentityServer.Security.Recaptcha
{
    public static class IdentityServerRecaptchaAppBuilderExtensions
    {
        public static IAppBuilder UseRecaptchaForAuthenticationRequests(this IAppBuilder app, 
                                                                        IdentityServerRecaptchaOptions options,
                                                                        Func<IRecaptchaValidationService> recaptchaValidationService)
        {
            if (app == null) throw new ArgumentNullException(nameof(app));
            if (options == null) throw new ArgumentNullException(nameof(options));

            if (recaptchaValidationService == null)
            {
                recaptchaValidationService = () => new DefaultRecaptchaValidationService();
            }

            RegisterRequestedChallengeType(app, options);

            app.UsePerOwinContext(recaptchaValidationService);
            app.Use<IdentityServerRecaptchaMiddleware>(options);

            return app;
        }

        private static void RegisterRequestedChallengeType(IAppBuilder app, IdentityServerRecaptchaOptions options)
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

        public static IAppBuilder UseRecaptchaForAuthenticationRequests(this IAppBuilder app,
                                                                        IdentityServerRecaptchaOptions options)
        {
            return app.UseRecaptchaForAuthenticationRequests(options,
                                                             () => new DefaultRecaptchaValidationService());
        }
    }
}