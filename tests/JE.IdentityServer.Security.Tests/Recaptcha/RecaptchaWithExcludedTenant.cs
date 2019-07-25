using System.Net;
using System.Threading.Tasks;
using FluentAssertions;
using JE.IdentityServer.Security.Recaptcha.Services;
using JE.IdentityServer.Security.Tests.Infrastructure;
using NUnit.Framework;

namespace JE.IdentityServer.Security.Tests.Recaptcha
{
    public class RecaptchaWithExcludedTenant
    {
        [Test]
        public async Task RecaptchaWithExcludedTenant_WitNonExcludedTenant_ShouldChallenge()
        {
            var ipAddress = "192.168.1.101";
            var username = "jeuser";
            var tenant = "uk";

            var identityServerBuilder = new IdentityServerWithRecaptcha()
                .WithExcludedTenantsMatching("es")
                .WithProtectedGrantType("password")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(1)
                .WithFailuresForIpAddress(ipAddress, 1);

            using (var server = identityServerBuilder.Build())
            {
                var response = await server.CreateNativeLoginRequest()
                    .WithUsername(username)
                    .WithPassword("Passw0rd")
                    .WithTenant(tenant)
                    .Build()
                    .PostAsync();
                response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

                identityServerBuilder.RecaptchaMonitor.HasIssuedChallenge.Should().BeTrue();
                identityServerBuilder.RecaptchaMonitor.UserContext.ShouldBeEquivalentTo(new RecaptchaUserContext
                {
                    Username = username,
                    IpAddress = ipAddress,
                    Tenant = tenant,
                    Device = new RecaptchaUserDevice()
                });
            }
        }

        [Test]
        public async Task RecaptchaWithExcludedTenant_WitExcludedTenant_ShouldNotChallenge()
        {
            var identityServerBuilder = new IdentityServerWithRecaptcha()
                .WithExcludedTenantsMatching("es")
                .WithProtectedGrantType("password")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(1)
                .WithFailuresForIpAddress("192.168.1.101", 1);


            using (var server = identityServerBuilder.Build())
            {
                var response = await server.CreateNativeLoginRequest()
                    .WithUsername("jeuser")
                    .WithPassword("Passw0rd")
                    .WithTenant("es")
                    .Build()
                    .PostAsync();
                response.StatusCode.Should().Be(HttpStatusCode.OK);

                identityServerBuilder.RecaptchaMonitor.HasIssuedChallenge.Should().BeFalse();
            }
        }
    }
}
