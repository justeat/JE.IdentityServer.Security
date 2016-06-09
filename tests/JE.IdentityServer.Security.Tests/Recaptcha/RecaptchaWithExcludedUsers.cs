using System.Net;
using System.Threading.Tasks;
using FluentAssertions;
using JE.IdentityServer.Security.Tests.Infrastructure;
using NUnit.Framework;

namespace JE.IdentityServer.Security.Tests.Recaptcha
{
    public class RecaptchaWithExcludedUsers
    {
        [Test]
        public async Task RecaptchaWithExcludedUsers_WitNonExcludedUser_ShouldChallenge()
        {
            using (var server = new IdentityServerWithRecaptcha()
                .WithExcludedUsernamesMatching("randomuser")
                .WithProtectedGrantType("password")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(1)
                .WithFailuresForIpAddress("192.168.1.101", 1).Build())
            {
                var response = await server.CreateNativeLoginRequest()
                    .WithUsername("jeuser")
                    .WithPassword("Passw0rd")
                    .Build()
                    .PostAsync();
                response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
            }
        }

        [Test]
        public async Task RecaptchaWithExcludedUsers_WitExcludedUser_ShouldNotChallenge()
        {
            using (var server = new IdentityServerWithRecaptcha()
                .WithExcludedUsernamesMatching("user")
                .WithProtectedGrantType("password")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(1)
                .WithFailuresForIpAddress("192.168.1.101", 1).Build())
            {
                var response = await server.CreateNativeLoginRequest()
                    .WithUsername("jeuser")
                    .WithPassword("Passw0rd")
                    .Build()
                    .PostAsync();
                response.StatusCode.Should().Be(HttpStatusCode.OK);
            }
        }

        [Test]
        public async Task RecaptchaWithExcludedUsers_WitNonExcludedSubnet_ShouldChallenge()
        {
            using (var server = new IdentityServerWithRecaptcha()
                .WithExcludedUsernamesMatching("randomuser")
                .WithProtectedGrantType("password")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(1)
                .WithFailuresForIpAddress("192.168.1.101", 1).Build())
            {
                var response = await server.CreateNativeLoginRequest()
                    .WithUsername("jeuser")
                    .WithPassword("Passw0rd")
                    .Build()
                    .PostAsync();
                response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
            }
        }
    }
}
