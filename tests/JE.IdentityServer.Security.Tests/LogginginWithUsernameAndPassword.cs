using System.Net;
using System.Threading.Tasks;
using FluentAssertions;
using JE.IdentityServer.Security.Tests.Infrastructure;
using NUnit.Framework;

namespace JE.IdentityServer.Security.Tests
{
    public class LoggingInWithUsernameAndPassword : WhenLoggingIn
    {
        [Test]
        public async Task ThenLogsInSuccessfully()
        {
            var response = await Server.CreateNativeLoginRequest()
                .WithUsername("jeuser")
                .WithPassword("Passw0rd")
                .Build()
                .PostAsync();
            response.StatusCode.Should().Be(HttpStatusCode.OK);
        }
    }
}
