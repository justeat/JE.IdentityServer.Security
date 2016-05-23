using System;
using System.Collections.Concurrent;
using JE.IdentityServer.Security.Resolver;
using Owin;

namespace JE.IdentityServer.Security.Tests.ServiceResolver
{
    public class Startup
    {
        public ConcurrentDictionary<Type, ConcurrentBag<string>> TypeOperations { get; private set; }

        public void Configuration(IAppBuilder app)
        {
            TypeOperations = new ConcurrentDictionary<Type, ConcurrentBag<string>>();

            app.UsePerOwinContext<ITextDataSource>(() => new TextDataSource(TypeOperations));
            app.Use<RandomTextSelectorMiddleware>();
        }
    }
}
