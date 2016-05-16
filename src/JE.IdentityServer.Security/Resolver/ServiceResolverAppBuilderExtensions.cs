using System;
using Microsoft.Owin;
using Owin;

namespace JE.IdentityServer.Security.Resolver
{
    public static class ServiceResolverAppBuilderExtensions
    {
        public static IAppBuilder UsePerOwinContext<T>(this IAppBuilder app, Func<T> createCallback)
            where T : class, IDisposable
        {
            return UsePerOwinContext<T>(app, (options, context) => createCallback());
        }

        private static IAppBuilder UsePerOwinContext<T>(this IAppBuilder app,
                              Func<ServiceFactoryOptions<T>, IOwinContext, T> createCallback) where T : class, IDisposable
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            if (createCallback == null)
            {
                throw new ArgumentNullException(nameof(createCallback));
            }

            app.Use(typeof(ServiceFactoryMiddleware<T, ServiceFactoryOptions<T>>),
                new ServiceFactoryOptions<T>
                {
                    Provider = new ServiceFactory<T> { OnCreate = createCallback }
                });

            return app;
        }
    }
}
