using System.Threading.Tasks;
using JE.IdentityServer.Security.Ravelin.Services;
using JE.IdentityServer.Security.Tests.Infrastructure;
using Moq;
using NUnit.Framework;

namespace JE.IdentityServer.Security.Tests.Ravelin
{
    public class RavelinRealtimeProtectionEnabled
    {
        [Test]
        public async Task RavelinRealtimeProtection_WhenEnabled_SuccessfulLoginSentToRavelin()
        {
            var ravelinSerivce = new Mock<IRavelinService>();

            using (var server = new IdentityServerWithRavelinRealtimeProtection()
                .WithProtectionEnabled()
                .WithRavelinService(ravelinSerivce.Object)
                .Build())
            {
                var response = await server.CreateNativeLoginRequest()
                    .WithUsername("jeuser.example.com")
                    .WithPassword("Passw0rd")
                    .WithTenant("uk")
                    .Build()
                    .PostAsync();


            }
        }

    }
}
