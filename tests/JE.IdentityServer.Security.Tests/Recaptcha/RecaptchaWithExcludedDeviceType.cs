using System.Net;
using System.Threading.Tasks;
using FluentAssertions;
using JE.IdentityServer.Security.Tests.Infrastructure;
using NUnit.Framework;

namespace JE.IdentityServer.Security.Tests.Recaptcha
{
    public class RecaptchaWithExcludedDeviceType
    {
        [Test]
        public async Task RecaptchaWithExcludedTenant_WitNonExcludedDevice_ShouldChallenge()
        {
            using (var server = new IdentityServerWithRecaptcha()
                .WithExcludedDevicesMatching("android")
                .WithProtectedGrantType("password")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(1)
                .WithFailuresForIpAddress("192.168.1.101", 1).Build())
            {
                var response = await server.CreateNativeLoginRequest()
                    .WithUsername("jeuser")
                    .WithPassword("Passw0rd")
                    .WithEncodedDevice("device-id", "ios", "device-name", "device-token")
                    .Build()
                    .PostAsync();
                response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
            }
        }

        [Test]
        public async Task RecaptchaWithExcludedTenant_WitExcludedDevice_ShouldNotChallenge()
        {
            using (var server = new IdentityServerWithRecaptcha()
                .WithExcludedDevicesMatching("ios")
                .WithProtectedGrantType("password")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(1)
                .WithFailuresForIpAddress("192.168.1.101", 1).Build())
            {
                var response = await server.CreateNativeLoginRequest()
                    .WithUsername("jeuser")
                    .WithPassword("Passw0rd")
                    .WithEncodedDevice("device-id", "ios", "device-name", "device-token")
                    .Build()
                    .PostAsync();
                response.StatusCode.Should().Be(HttpStatusCode.OK);
            }
        }

        [Test]
        public async Task RecaptchaWithExcludedTenant_WitNonExcludedDeviceType_ShouldChallenge()
        {
            using (var server = new IdentityServerWithRecaptcha()
                .WithExcludedDevicesMatching("android")
                .WithProtectedGrantType("password")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(1)
                .WithFailuresForIpAddress("192.168.1.101", 1).Build())
            {
                var response = await server.CreateNativeLoginRequest()
                    .WithUsername("jeuser")
                    .WithPassword("Passw0rd")
                    .WithDeviceType("ios")
                    .Build()
                    .PostAsync();
                response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
            }
        }

        [Test]
        public async Task RecaptchaWithExcludedTenant_WitExcludedDeviceType_ShouldNotChallenge()
        {
            using (var server = new IdentityServerWithRecaptcha()
                .WithExcludedDevicesMatching("ios")
                .WithProtectedGrantType("password")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(1)
                .WithFailuresForIpAddress("192.168.1.101", 1).Build())
            {
                var response = await server.CreateNativeLoginRequest()
                    .WithUsername("jeuser")
                    .WithPassword("Passw0rd")
                    .WithDeviceType("ios")
                    .Build()
                    .PostAsync();
                response.StatusCode.Should().Be(HttpStatusCode.OK);
            }
        }
    }
}