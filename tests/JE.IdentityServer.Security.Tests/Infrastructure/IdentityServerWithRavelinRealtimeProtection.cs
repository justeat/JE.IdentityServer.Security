using System;
using JE.IdentityServer.Security.Resolver;
using JE.IdentityServer.Security.Services;
using JE.IdentityServer.Security.Throttling;
using Microsoft.Owin.Testing;

namespace JE.IdentityServer.Security.Tests.Infrastructure
{
    public class IdentityServerWithRavelinRealtimeProtection : IDisposable
    {
        private string _protectedPath = "/identity/connect/token";
        private TestServer _testServer;

        public void Dispose()
        {
            _testServer?.Dispose();
        }

        public TestServer Build()
        {
            _testServer = TestServer.Create(app =>
            {
//                app.UsePerOwinContext<ILoginStatistics>(() => _loginStatistics);
                app.Use<RavelinRealtimeProtection>(null);
                app.UseInMemoryIdentityServer();
            });

            return _testServer;
        }
    }
}
