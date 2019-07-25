using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using FluentAssertions;
using JE.IdentityServer.Security.Recaptcha.Services;
using JE.IdentityServer.Security.Resources;
using JE.IdentityServer.Security.Tests.Infrastructure;
using NUnit.Framework;

namespace JE.IdentityServer.Security.Tests.Recaptcha
{
    public class RecaptchaWithValidCredentials
    {
        private const int NumberOfAllowedLoginFailures = 1;

        [Test]
        public async Task RecaptchaWithValidCredentials_WithUnsupportedGrantType_ShouldNotChallenge()
        {
            var identityServerBuilder = new IdentityServerWithRecaptcha()
                .WithNumberOfAllowedLoginFailuresPerIpAddress(NumberOfAllowedLoginFailures);

            using (var server = identityServerBuilder.Build())
            {
                var response = await server.CreateNativeLoginRequest()
                    .WithUsername("jeuser")
                    .WithPassword("Passw0rd")
                    .Build()
                    .PostAsync();
                response.StatusCode.Should().Be(HttpStatusCode.OK);
                var tokenResponse = await response.Content.ReadAsAsync<TokenResponseModel>();
                tokenResponse.AccessToken.Should().NotBeNullOrEmpty();

                identityServerBuilder.RecaptchaMonitor.HasIssuedChallenge.Should().BeFalse();
                identityServerBuilder.RecaptchaMonitor.HasCompletedChallenge.Should().BeFalse();
            }
        }

        [Test]
        public async Task RecaptchaWithValidCredentials_WithUnsupportedGrantType_ShouldReport()
        {
            var identityServerBuilder = new IdentityServerWithRecaptcha()
                .WithProtectedGrantType("password")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(NumberOfAllowedLoginFailures);

            using (var server = identityServerBuilder.Build())
            {
                await server.CreateNativeLoginRequest()
                    .WithUsername("jeuser")
                    .WithPassword("Passw0rd")
                    .Build()
                    .PostAsync();
                identityServerBuilder.LoginStatistics.TotalNumberOfNonChallengesForFailedLogins.Should().Be(1);
                identityServerBuilder.LoginStatistics.TotalNumberOfChallengesForFailedLogins.Should().Be(0);
            }
        }

        [Test]
        public async Task RecaptchaWithValidCredentials_WithDefaultChallengeType_ShouldChallengeAsUnauthorized()
        {
            var ipAddress = "192.168.1.101";
            var username = "jeuser";

            var identityServerBuilder = new IdentityServerWithRecaptcha()
                .WithProtectedGrantType("password")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(NumberOfAllowedLoginFailures)
                .WithFailuresForIpAddress(ipAddress, NumberOfAllowedLoginFailures);

            using (var server = identityServerBuilder.Build())
            {
                var response = await server
                    .CreateNativeLoginRequest()
                    .WithUsername(username)
                    .WithPassword("Passw0rd")
                    .WithGrantType("password")
                    .Build()
                    .PostAsync();
                response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
                response.Headers.WwwAuthenticate.Should().Contain(h => h.Scheme == "recaptcha");
                response.Headers.WwwAuthenticate.Should().Contain(h => h.Parameter == @"url=""/recaptcha/platform""");

                identityServerBuilder.RecaptchaMonitor.HasIssuedChallenge.Should().BeTrue();
                identityServerBuilder.RecaptchaMonitor.HasCompletedChallenge.Should().BeFalse();
                identityServerBuilder.RecaptchaMonitor.UserContext.Username.Should().Be(username);
                identityServerBuilder.RecaptchaMonitor.UserContext.IpAddress.Should().Be(ipAddress);
            }
        }

        [Test]
        public async Task RecaptchaWithValidCredentials_WithDefaultChallengeType_ShouldReport()
        {
            var ipAddress = "192.168.1.101";
            var username = "jeuser";

            var identityServerBuilder = new IdentityServerWithRecaptcha()
                .WithProtectedGrantType("password")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(NumberOfAllowedLoginFailures)
                .WithFailuresForIpAddress(ipAddress, NumberOfAllowedLoginFailures);

            using (var server = identityServerBuilder.Build())
            {
                await server.CreateNativeLoginRequest()
                    .WithUsername("jeuser")
                    .WithPassword("Passw0rd")
                    .WithGrantType("password")
                    .Build()
                    .PostAsync();

                identityServerBuilder.LoginStatistics.TotalNumberOfChallengesForFailedLogins.Should().Be(1);

                identityServerBuilder.RecaptchaMonitor.HasIssuedChallenge.Should().BeTrue();
                identityServerBuilder.RecaptchaMonitor.HasCompletedChallenge.Should().BeFalse();
                identityServerBuilder.RecaptchaMonitor.UserContext.ShouldBeEquivalentTo(new RecaptchaUserContext
                {
                    Username = username,
                    IpAddress = ipAddress,
                    Device = new RecaptchaUserDevice()
                });
            }
        }

        [Test]
        public async Task RecaptchaWithValidCredentials_WithDefaultChallengeType_ShouldContainExpectedRecaptchaBody()
        {
            var identityServerBuilder = new IdentityServerWithRecaptcha()
                .WithProtectedGrantType("password")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(NumberOfAllowedLoginFailures)
                .WithFailuresForIpAddress("192.168.1.101", NumberOfAllowedLoginFailures);

            using (var server = identityServerBuilder.Build())
            {
                var response = await server.CreateNativeLoginRequest()
                    .WithUsername("jeuser")
                    .WithPassword("Passw0rd")
                    .WithGrantType("password")
                    .Build()
                    .PostAsync();
                response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
                var resource = await response.Content.ReadAsAsync<IdentityServerUnauthorizedChallengeResource>();
                resource.LinkToChallenge.Should().Be("/recaptcha/platform");
                resource.Description.Should().Contain("add the x-recaptcha-answer");
                resource.ChallengeHtml.Should().Contain("<script src=\"https://www.google.com/recaptcha/api.js?hl=en-GB\" async defer>");

                identityServerBuilder.RecaptchaMonitor.HasIssuedChallenge.Should().BeTrue();
                identityServerBuilder.RecaptchaMonitor.HasCompletedChallenge.Should().BeFalse();
            }
        }

        [Test]
        public async Task RecaptchaWithValidCredentials_WithBadRequestChallengeType_ShouldChallengeAsBadRequest()
        {
            var ipAddress = "192.168.1.101";
            var username = "jeuser";

            var identityServerBuilder = new IdentityServerWithRecaptcha()
                .WithProtectedGrantType("password")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(NumberOfAllowedLoginFailures)
                .WithFailuresForIpAddress(ipAddress, NumberOfAllowedLoginFailures)
                .WithChallengeAsBadRequest()
                .WithNumberOfAllowedLoginFailuresPerIpAddress(NumberOfAllowedLoginFailures);

            using (var server = identityServerBuilder.Build())
            {
                var response = await server
                    .CreateNativeLoginRequest()
                    .WithUsername(username)
                    .WithPassword("Passw0rd")
                    .WithGrantType("password")
                    .Build()
                    .PostAsync();
                response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

                identityServerBuilder.RecaptchaMonitor.HasIssuedChallenge.Should().BeTrue();
                identityServerBuilder.RecaptchaMonitor.HasCompletedChallenge.Should().BeFalse();
                identityServerBuilder.RecaptchaMonitor.UserContext.ShouldBeEquivalentTo(new RecaptchaUserContext
                {
                    Username = username,
                    IpAddress = ipAddress,
                    Device = new RecaptchaUserDevice()
                });
            }
        }

        [Test]
        public async Task RecaptchaWithValidCredentials_WithBadRequestChallengeType_ShouldContainExpectedRecaptchaBody()
        {
            var ipAddress = "192.168.1.101";
            var username = "jeuser";

            var identityServerBuilder = new IdentityServerWithRecaptcha()
                .WithProtectedGrantType("password")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(NumberOfAllowedLoginFailures)
                .WithFailuresForIpAddress(ipAddress, NumberOfAllowedLoginFailures)
                .WithChallengeAsBadRequest()
                .WithNumberOfAllowedLoginFailuresPerIpAddress(NumberOfAllowedLoginFailures);

            using (var server = identityServerBuilder.Build())
            {
                var response = await server.CreateNativeLoginRequest()
                    .WithUsername(username)
                    .WithPassword("Passw0rd")
                    .WithGrantType("password")
                    .Build()
                    .PostAsync();
                response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
                var resource = await response.Content.ReadAsAsync<IdentityServerBadRequestChallengeResource>();
                resource.Message.Should().Contain("Please complete the Recaptcha");
                resource.ChallengeHtml.Should().Contain("<script src=\"https://www.google.com/recaptcha/api.js?hl=en-GB\" async defer>");

                identityServerBuilder.RecaptchaMonitor.HasIssuedChallenge.Should().BeTrue();
                identityServerBuilder.RecaptchaMonitor.HasCompletedChallenge.Should().BeFalse();
                identityServerBuilder.RecaptchaMonitor.UserContext.ShouldBeEquivalentTo(new RecaptchaUserContext
                {
                    Username = username,
                    IpAddress = ipAddress,
                    Device = new RecaptchaUserDevice()
                });
            }
        }
    }
}
