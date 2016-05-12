using System;
using System.Net.Http;
using Microsoft.Owin.Testing;
using NUnit.Framework;

namespace JE.IdentityServer.Security.Tests.Infrastructure
{
    public class WhenLoggingIn : IDisposable
    {
        protected HttpResponseMessage Response;
        protected TestServer Server { get; private set; }

        [OneTimeSetUp]
        public void BeforeAll()
        {
            Server = TestServer.Create(app =>
            {
                var s = new IdentityServerStartup();
                s.Configuration(app);
            });
        }

        [OneTimeTearDown]
        public void Dispose()
        {
            Server?.Dispose();
        }
    }
}