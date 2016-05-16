using System;
using System.Threading.Tasks;
using JE.IdentityServer.Security.Extensions;
using Microsoft.Owin;

namespace JE.IdentityServer.Security.Resolver
{
    public class ServiceFactoryMiddleware<TResult, TOptions> : OwinMiddleware
        where TResult : IDisposable
        where TOptions : ServiceFactoryOptions<TResult>
    {
        public TOptions Options { get; private set; }

        public ServiceFactoryMiddleware(OwinMiddleware next, TOptions options)
            : base(next)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            if (options.Provider == null)
            {
                throw new ArgumentNullException("options.Provider");
            }

            Options = options;
        }

        public override async Task Invoke(IOwinContext context)
        {
            var instance = Options.Provider.Create(Options, context);
            try
            {
                context.Set(instance);
                if (Next != null)
                {
                    await Next.Invoke(context);
                }
            }
            finally
            {
                Options.Provider.Dispose(Options, instance);
            }
        }
    }
}