using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using FluentAssertions;
using JE.IdentityServer.Security.Resources;
using JE.IdentityServer.Security.Tests.Infrastructure;
using NUnit.Framework;

namespace JE.IdentityServer.Security.Tests.Recaptcha
{
    public class RecaptchaResponseBodyStructure
    {
        private const int NumberOfAllowedLoginFailures = 1;

        [Test]
        public async Task RecaptchaResponseBody_WithBadRequestChallengeType_ShouldContainExpectedRecaptchaBody()
        {
            using (var server = new IdentityServerWithRecaptcha()
                .WithProtectedGrantType("password")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(NumberOfAllowedLoginFailures)
                .WithFailuresForIpAddress("192.168.1.101", NumberOfAllowedLoginFailures)
                .WithChallengeAsBadRequest()
                .WithPublicKey("recaptcha-public-key")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(NumberOfAllowedLoginFailures).Build())
            {
                var response = await server.CreateNativeLoginRequest()
                    .WithUsername("jeuser")
                    .WithPassword("Passw0rd")
                    .WithGrantType("password")
                    .WithLanguageCode("es-ES")
                    .Build()
                    .PostAsync();
                response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
                var resource = await response.Content.ReadAsAsync<IdentityServerBadRequestChallengeResource>();
                resource.Message.Should().Contain("Please complete the Recaptcha");
                resource.ChallengeHtml.Should().Contain("<script src=\"https://www.google.com/recaptcha/api.js?hl=es-ES\" async defer>");
                resource.ChallengeHtml.Should().Contain("<div class=\"g-recaptcha\" data-sitekey=\"recaptcha-public-key\"></div>");
            }
        }

        [Test]
        public async Task RecaptchaResponseBody_WithDefaultChallengeType_ShouldContainExpectedRecaptchaBody()
        {
            using (var server = new IdentityServerWithRecaptcha()
                .WithProtectedGrantType("password")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(NumberOfAllowedLoginFailures)
                .WithFailuresForIpAddress("192.168.1.101", NumberOfAllowedLoginFailures)
                .WithPublicKey("recaptcha-public-key")
                .Build())
            {
                var response = await server.CreateNativeLoginRequest()
                    .WithUsername("jeuser")
                    .WithPassword("Passw0rd")
                    .WithGrantType("password")
                    .WithLanguageCode("es-ES")
                    .Build()
                    .PostAsync();
                response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
                var resource = await response.Content.ReadAsAsync<IdentityServerUnauthorizedChallengeResource>();
                resource.LinkToChallenge.Should().Be("/recaptcha/platform");
                resource.Description.Should().Contain("add the x-recaptcha-answer");
                resource.ChallengeHtml.Should().Contain("<script src=\"https://www.google.com/recaptcha/api.js?hl=es-ES\" async defer>");
                resource.ChallengeHtml.Should().Contain("<div class=\"g-recaptcha\" data-sitekey=\"recaptcha-public-key\"></div>");
            }
        }

        [Test]
        public async Task RecaptchaResponseBody_WithDefaultClients_ShouldContainFullRecaptchaHtml()
        {
            using (var server = new IdentityServerWithRecaptcha()
                .WithProtectedGrantType("password")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(NumberOfAllowedLoginFailures)
                .WithFailuresForIpAddress("192.168.1.101", NumberOfAllowedLoginFailures)
                .WithPublicKey("recaptcha-public-key")
                .Build())
            {
                var response = await server.CreateNativeLoginRequest()
                    .WithUsername("jeuser")
                    .WithPassword("Passw0rd")
                    .WithGrantType("password")
                    .WithLanguageCode("es-ES")
                    .Build()
                    .PostAsync();
                response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
                var resource = await response.Content.ReadAsAsync<IdentityServerUnauthorizedChallengeResource>();
                resource.ChallengeHtml.Should().StartWith("<!DOCTYPE html>");
            }
        }

        [Test]
        public async Task RecaptchaResponseBody_WithClientSupportingPartials_ShouldContainPartialRecaptchaHtml()
        {
            using (var server = new IdentityServerWithRecaptcha()
                .WithProtectedGrantType("password")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(NumberOfAllowedLoginFailures)
                .WithFailuresForIpAddress("192.168.1.101", NumberOfAllowedLoginFailures)
                .WithWebClients()
                .WithPublicKey("recaptcha-public-key")
                .Build())
            {
                var response = await server.CreateNativeLoginRequest()
                    .WithUsername("jeuser")
                    .WithPassword("Passw0rd")
                    .WithGrantType("password")
                    .WithLanguageCode("es-ES")
                    .Build()
                    .PostAsync();
                response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
                var resource = await response.Content.ReadAsAsync<IdentityServerUnauthorizedChallengeResource>();
                resource.ChallengeHtml.Should().StartWith("<script src=\"");
            }
        }
    }
}
