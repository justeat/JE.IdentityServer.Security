using System.Net;
using System.Threading.Tasks;
using FluentAssertions;
using JE.IdentityServer.Security.Recaptcha.Services;
using JE.IdentityServer.Security.Resources;
using JE.IdentityServer.Security.Tests.Infrastructure;
using NUnit.Framework;

namespace JE.IdentityServer.Security.Tests.Recaptcha
{
    public class RecaptchaWithExcludedDeviceType
    {
        [Test]
        public async Task RecaptchaWithExcludedTenant_WitNonExcludedDevice_ShouldChallenge()
        {
            var ipAddress = "192.168.1.101";
            var username = "jeuser";
            var deviceId = "device-id";
            var deviceName = "device-name";
            var deviceType = "device-type";
            var deviceToken = "device-token";

            var identityServerBuilder = new IdentityServerWithRecaptcha()
                .WithExcludedDevicesMatching("android")
                .WithProtectedGrantType("password")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(1)
                .WithFailuresForIpAddress("192.168.1.101", 1);

            using (var server = identityServerBuilder.Build())
            {
                var response = await server.CreateNativeLoginRequest()
                    .WithUsername(username)
                    .WithPassword("Passw0rd")
                    .WithEncodedDevice(deviceId, deviceType, deviceName, deviceToken)
                    .Build()
                    .PostAsync();
                response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

                identityServerBuilder.RecaptchaMonitor.HasIssuedChallenge.Should().BeTrue();
                identityServerBuilder.RecaptchaMonitor.HasCompletedChallenge.Should().BeFalse();

                identityServerBuilder.RecaptchaMonitor.UserContext.ShouldBeEquivalentTo(
                    new RecaptchaUserContext
                    {
                        Username = username,
                        IpAddress = ipAddress,
                        Device = new RecaptchaUserDevice
                        {
                            Id = deviceId,
                            Type = deviceType,
                            Name = deviceName,
                            Token = deviceToken
                        }
                    });
            }
        }

        [Test]
        public async Task RecaptchaWithExcludedTenant_WitExcludedDevice_ShouldNotChallenge()
        {
            var identityServerBuilder = new IdentityServerWithRecaptcha()
                .WithExcludedDevicesMatching("ios")
                .WithProtectedGrantType("password")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(1)
                .WithFailuresForIpAddress("192.168.1.101", 1);

            using (var server = identityServerBuilder.Build())
            {
                var response = await server.CreateNativeLoginRequest()
                    .WithUsername("jeuser")
                    .WithPassword("Passw0rd")
                    .WithEncodedDevice("device-id", "ios", "device-name", "device-token")
                    .Build()
                    .PostAsync();
                response.StatusCode.Should().Be(HttpStatusCode.OK);

                identityServerBuilder.RecaptchaMonitor.HasIssuedChallenge.Should().BeFalse();
            }
        }

        [Test]
        public async Task RecaptchaWithExcludedTenant_WitNonExcludedDeviceType_ShouldChallenge()
        {
            var identityServerBuilder = new IdentityServerWithRecaptcha()
                .WithExcludedDevicesMatching("android")
                .WithProtectedGrantType("password")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(1)
                .WithFailuresForIpAddress("192.168.1.101", 1);

            using (var server = identityServerBuilder.Build())
            {
                var response = await server.CreateNativeLoginRequest()
                    .WithUsername("jeuser")
                    .WithPassword("Passw0rd")
                    .WithDeviceType("ios")
                    .Build()
                    .PostAsync();
                response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

                identityServerBuilder.RecaptchaMonitor.HasIssuedChallenge.Should().BeTrue();
                identityServerBuilder.RecaptchaMonitor.HasCompletedChallenge.Should().BeFalse();
            }
        }

        [Test]
        public async Task RecaptchaWithExcludedTenant_WitExcludedDeviceType_ShouldNotChallenge()
        {
            var identityServerBuilder = new IdentityServerWithRecaptcha()
                .WithExcludedDevicesMatching("ios")
                .WithProtectedGrantType("password")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(1)
                .WithFailuresForIpAddress("192.168.1.101", 1);

            using (var server = identityServerBuilder.Build())
            {
                var response = await server.CreateNativeLoginRequest()
                    .WithUsername("jeuser")
                    .WithPassword("Passw0rd")
                    .WithDeviceType("ios")
                    .Build()
                    .PostAsync();
                response.StatusCode.Should().Be(HttpStatusCode.OK);

                identityServerBuilder.RecaptchaMonitor.HasIssuedChallenge.Should().BeFalse();
            }
        }
    }
}
