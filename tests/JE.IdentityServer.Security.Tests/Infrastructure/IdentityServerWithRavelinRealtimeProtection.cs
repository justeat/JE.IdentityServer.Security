using System;
using JE.IdentityServer.Security.Ravelin.Services;
using JE.IdentityServer.Security.Resolver;
using JE.IdentityServer.Security.Services;
using JE.IdentityServer.Security.Throttling;
using Microsoft.Owin.Testing;
using Owin;

namespace JE.IdentityServer.Security.Tests.Infrastructure
{
    public class IdentityServerWithRavelinRealtimeProtection : IDisposable
    {
        private string _protectedPath = "/identity/connect/token";
        private bool _ravelinRealtimeProtectionEnabled;
        private TestServer _testServer;
        private IRavelinService _ravelinService;

        public IdentityServerWithRavelinRealtimeProtection WithRavelinService(IRavelinService ravelinService)
        {
            _ravelinService = ravelinService;
            return this;
        }

        public IdentityServerWithRavelinRealtimeProtection WithProtectionEnabled()
        {
            _ravelinRealtimeProtectionEnabled = true;
            return this;
        }
        public IdentityServerWithRavelinRealtimeProtection WithProtectionDisabled()
        {
            _ravelinRealtimeProtectionEnabled = false;
            return this;
        }


        public void Dispose()
        {
            _testServer?.Dispose();
        }

        public TestServer Build()
        {
            _testServer = TestServer.Create(app =>
            {
                app.Use<RavelinRealtimeProtection>(new RavelinRealtimeProtectionOptions
                {
                    RavelinService = _ravelinService,
                    Enabled = _ravelinRealtimeProtectionEnabled
                });

                app.UseInMemoryIdentityServer();
            });

            return _testServer;
        }
    }
}
