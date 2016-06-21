using System.Net;
using System.Threading.Tasks;
using FluentAssertions;
using JE.IdentityServer.Security.Tests.Infrastructure;
using NUnit.Framework;

namespace JE.IdentityServer.Security.Tests.Recaptcha
{
    public class RecaptchaWithExcludedOsVersion
    {
        [Test]
        public async Task RecaptchaWithExcludedOsVersion_WitNonExcludedOsVersion_ShouldChallenge()
        {
            using (var server = new IdentityServerWithRecaptcha()
                .WithExcludedOsVersionsMatching("4\\.0")
                .WithProtectedGrantType("password")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(1)
                .WithFailuresForIpAddress("192.168.1.101", 1).Build())
            {
                var response = await server.CreateNativeLoginRequest()
                    .WithUsername("jeuser")
                    .WithPassword("Passw0rd")
                    .WithOsVersion("5.0")
                    .Build()
                    .PostAsync();
                response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
            }
        }

        [Test]
        public async Task RecaptchaWithExcludedOsVersion_WithExcludedOsVersion_ShouldNotChallenge()
        {
            using (var server = new IdentityServerWithRecaptcha()
                .WithExcludedOsVersionsMatching("5\\.0")
                .WithProtectedGrantType("password")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(1)
                .WithFailuresForIpAddress("192.168.1.101", 1).Build())
            {
                var response = await server.CreateNativeLoginRequest()
                    .WithUsername("jeuser")
                    .WithPassword("Passw0rd")
                    .WithOsVersion("5.0")
                    .Build()
                    .PostAsync();
                response.StatusCode.Should().Be(HttpStatusCode.OK);
            }
        }
    }
}