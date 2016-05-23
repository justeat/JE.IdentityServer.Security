using System;
using Microsoft.Owin;

namespace JE.IdentityServer.Security.Resolver
{
    public interface IDependencyFactory<T> where T : IDisposable
    {
        T Create(ServiceFactoryOptions<T> options, IOwinContext context);
        void Dispose(ServiceFactoryOptions<T> options, T instance);
    }
}
