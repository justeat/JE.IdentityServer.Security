using System;
using Microsoft.Owin;

namespace JE.IdentityServer.Security.Resolver
{
    public class ServiceFactory<T> : IDependencyFactory<T> where T : class, IDisposable
    {
        public ServiceFactory()
        {
            OnDispose = (options, instance) => { };
            OnCreate = (options, context) => null;
        }

        public Func<ServiceFactoryOptions<T>, IOwinContext, T> OnCreate { get; set; }

        public Action<ServiceFactoryOptions<T>, T> OnDispose { get; set; }

        public virtual T Create(ServiceFactoryOptions<T> options, IOwinContext context)
        {
            return OnCreate(options, context);
        }

        public virtual void Dispose(ServiceFactoryOptions<T> options, T instance)
        {
            OnDispose(options, instance);
        }
    }
}