using System;
using System.Collections.Generic;
using Owin;

namespace JE.IdentityServer.Security.Recaptcha
{
    public interface IRecaptchaMiddlewareBuilder : IAppBuilder
    {
        IdentityServerRecaptchaOptions Options { get; }
    }

    public class RecaptchaMiddlewareBuilder : IRecaptchaMiddlewareBuilder
    {
        private readonly IAppBuilder _appBuilder;

        public RecaptchaMiddlewareBuilder(IAppBuilder appBuilder, IdentityServerRecaptchaOptions recaptchaOptions)
        {
            _appBuilder = appBuilder;
            Options = recaptchaOptions;
        }

        public IAppBuilder Use(object middleware, params object[] args) => _appBuilder.Use(middleware, args);

        public object Build(Type returnType) => _appBuilder.Build(returnType);

        public IAppBuilder New() => _appBuilder.New();

        public IDictionary<string, object> Properties => _appBuilder.Properties;

        public IdentityServerRecaptchaOptions Options { get; }
    }
}
