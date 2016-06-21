using System.Net;
using System.Threading.Tasks;
using FluentAssertions;
using JE.IdentityServer.Security.Tests.Infrastructure;
using NUnit.Framework;

namespace JE.IdentityServer.Security.Tests.Recaptcha
{
    public class RecaptchaWithExcludedTenant
    {
        [Test]
        public async Task RecaptchaWithExcludedTenant_WitNonExcludedTenant_ShouldChallenge()
        {
            using (var server = new IdentityServerWithRecaptcha()
                .WithExcludedTenantsMatching("es")
                .WithProtectedGrantType("password")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(1)
                .WithFailuresForIpAddress("192.168.1.101", 1).Build())
            {
                var response = await server.CreateNativeLoginRequest()
                    .WithUsername("jeuser")
                    .WithPassword("Passw0rd")
                    .WithTenant("uk")
                    .Build()
                    .PostAsync();
                response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
            }
        }

        [Test]
        public async Task RecaptchaWithExcludedTenant_WitExcludedTenant_ShouldNotChallenge()
        {
            using (var server = new IdentityServerWithRecaptcha()
                .WithExcludedTenantsMatching("es")
                .WithProtectedGrantType("password")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(1)
                .WithFailuresForIpAddress("192.168.1.101", 1).Build())
            {
                var response = await server.CreateNativeLoginRequest()
                    .WithUsername("jeuser")
                    .WithPassword("Passw0rd")
                    .WithTenant("es")
                    .Build()
                    .PostAsync();
                response.StatusCode.Should().Be(HttpStatusCode.OK);
            }
        }
    }
}