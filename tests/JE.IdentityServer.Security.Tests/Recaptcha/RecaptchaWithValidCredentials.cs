using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using FluentAssertions;
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
            using (var server = new IdentityServerWithRecaptcha()
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
            using (var server = new IdentityServerWithRecaptcha()
                .WithProtectedGrantType("password")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(NumberOfAllowedLoginFailures)
                .WithFailuresForIpAddress("192.168.1.101", NumberOfAllowedLoginFailures)
                .Build())
            {
                var response = await server.CreateNativeLoginRequest()
                    .WithUsername("jeuser")
                    .WithPassword("Passw0rd")
                    .WithGrantType("password")
                    .Build()
                    .PostAsync();
                response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
                response.Headers.WwwAuthenticate.Should().Contain(h => h.Scheme == "recaptcha");
                response.Headers.WwwAuthenticate.Should().Contain(h => h.Parameter == @"url=""/recaptcha/platform""");
            }
        }

        [Test]
        public async Task RecaptchaWithValidCredentials_WithDefaultChallengeType_ShouldReport()
        {
            var identityServerBuilder = new IdentityServerWithRecaptcha()
                .WithProtectedGrantType("password")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(NumberOfAllowedLoginFailures)
                .WithFailuresForIpAddress("192.168.1.101", NumberOfAllowedLoginFailures);
            using (var server = identityServerBuilder.Build())
            {
                await server.CreateNativeLoginRequest()
                    .WithUsername("jeuser")
                    .WithPassword("Passw0rd")
                    .WithGrantType("password")
                    .Build()
                    .PostAsync();

                identityServerBuilder.LoginStatistics.TotalNumberOfChallengesForFailedLogins.Should().Be(1);
            }
        }

        [Test]
        public async Task RecaptchaWithValidCredentials_WithDefaultChallengeType_ShouldContainExpectedRecaptchaBody()
        {
            using (var server = new IdentityServerWithRecaptcha()
                .WithProtectedGrantType("password")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(NumberOfAllowedLoginFailures)
                .WithFailuresForIpAddress("192.168.1.101", NumberOfAllowedLoginFailures)
                .Build())
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
            }
        }

        [Test]
        public async Task RecaptchaWithValidCredentials_WithBadRequestChallengeType_ShouldChallengAsBadRequest()
        {
            using (var server = new IdentityServerWithRecaptcha()
                .WithProtectedGrantType("password")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(NumberOfAllowedLoginFailures)
                .WithFailuresForIpAddress("192.168.1.101", NumberOfAllowedLoginFailures)
                .WithChallengeAsBadRequest()
                .WithNumberOfAllowedLoginFailuresPerIpAddress(NumberOfAllowedLoginFailures).Build())
            {
                var response = await server.CreateNativeLoginRequest()
                    .WithUsername("jeuser")
                    .WithPassword("Passw0rd")
                    .WithGrantType("password")
                    .Build()
                    .PostAsync();
                response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
            }
        }

        [Test]
        public async Task RecaptchaWithValidCredentials_WithBadRequestChallengeType_ShouldContainExpectedRecaptchaBody()
        {
            using (var server = new IdentityServerWithRecaptcha()
                .WithProtectedGrantType("password")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(NumberOfAllowedLoginFailures)
                .WithFailuresForIpAddress("192.168.1.101", NumberOfAllowedLoginFailures)
                .WithChallengeAsBadRequest()
                .WithNumberOfAllowedLoginFailuresPerIpAddress(NumberOfAllowedLoginFailures).Build())
            {
                var response = await server.CreateNativeLoginRequest()
                    .WithUsername("jeuser")
                    .WithPassword("Passw0rd")
                    .WithGrantType("password")
                    .Build()
                    .PostAsync();
                response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
                var resource = await response.Content.ReadAsAsync<IdentityServerBadRequestChallengeResource>();
                resource.Message.Should().Contain("Please complete the Recaptcha");
                resource.ChallengeHtml.Should().Contain("<script src=\"https://www.google.com/recaptcha/api.js?hl=en-GB\" async defer>");
            }
        }
    }
}