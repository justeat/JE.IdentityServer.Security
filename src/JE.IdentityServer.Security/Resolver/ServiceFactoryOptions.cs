using System;

namespace JE.IdentityServer.Security.Resolver
{
    public class ServiceFactoryOptions<T> where T : IDisposable
    {
        public IDependencyFactory<T> Provider { get; set; }
    }
}