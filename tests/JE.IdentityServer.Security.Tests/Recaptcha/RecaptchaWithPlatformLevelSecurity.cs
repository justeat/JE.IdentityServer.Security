using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using FluentAssertions;
using JE.IdentityServer.Security.Tests.Infrastructure;
using NUnit.Framework;

namespace JE.IdentityServer.Security.Tests.Recaptcha
{
    public class RecaptchaWithPlatformLevelSecurity
    {
        private const int NumberOfAllowedLoginFailures = 1;

        [Test]
        public async Task RecaptchaWithPlatformLevelSecurity_WithShieldsDown_ShouldNotChallenge()
        {
            using (var server = new IdentityServerWithRecaptcha()
                .WithPlatformSecurityShieldsDown()
                .WithProtectedGrantType("password")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(NumberOfAllowedLoginFailures).Build())
            {
                var response = await server.CreateNativeLoginRequest()
                    .WithUsername("jeuser")
                    .WithPassword("Passw0rd")
                    .Build()
                    .PostAsync();
                response.StatusCode.Should().Be(HttpStatusCode.OK);
                var tokenResponse = await response.Content.ReadAsAsync<TokenResponseModel>();
                tokenResponse.AccessToken.Should().NotBeNullOrEmpty();
            }
        }

        [Test]
        public async Task RecaptchaWithPlatformLevelSecurity_WithShieldsUp_ShouldChallenge()
        {
            using (var server = new IdentityServerWithRecaptcha()
                .WithPlatformSecurityShieldsUp()
                .WithProtectedGrantType("password")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(NumberOfAllowedLoginFailures).Build())
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
