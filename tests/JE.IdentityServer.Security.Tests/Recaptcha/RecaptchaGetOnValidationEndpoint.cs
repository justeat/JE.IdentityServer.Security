using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using FluentAssertions;
using JE.IdentityServer.Security.Resources;
using JE.IdentityServer.Security.Tests.Infrastructure;
using NUnit.Framework;

namespace JE.IdentityServer.Security.Tests.Recaptcha
{
    public class RecaptchaGetOnValidationEndpoint
    {
        private const int NumberOfAllowedLoginFailures = 1;

        [Test]
        public async Task RecaptchaGetOnValidationEndpoint_WithExceededLoginFailures_ShouldReturnUnauthorized()
        {
            using (var server = new IdentityServerWithRecaptchaValidationEndpoint()
                .WithProtectedGrantType("password")
                .WithFailuresForIpAddress("192.168.1.101", NumberOfAllowedLoginFailures)
                .WithPublicKey("recaptcha-public-key")
                .WithRecaptchaValidationEndpoint("/recaptcha/validation")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(NumberOfAllowedLoginFailures).Build())
            {
                var response = await server.CreateRequest("/recaptcha/validation")
                    .AddHeader("HTTP_X_FORWARDED_FOR", "192.168.1.101")
                    .GetAsync();
                response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
            }
        }

        [Test]
        public async Task RecaptchaGetOnValidationEndpoint_WithExceededLoginFailures_ShouldContainExpectedRecaptchaBody()
        {
            using (var server = new IdentityServerWithRecaptchaValidationEndpoint()
                .WithProtectedGrantType("password")
                .WithFailuresForIpAddress("192.168.1.101", NumberOfAllowedLoginFailures)
                .WithPublicKey("recaptcha-public-key")
                .WithRecaptchaValidationEndpoint("/recaptcha/validation")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(NumberOfAllowedLoginFailures).Build())
            {
                var response = await server.CreateRequest("/recaptcha/validation")
                    .AddHeader("HTTP_X_FORWARDED_FOR", "192.168.1.101")
                    .GetAsync();
                var resource = await response.Content.ReadAsAsync<IdentityServerUnauthorizedChallengeResource>();
                resource.ChallengeHtml.Should().StartWith("<script src=\"");
            }
        }

        [Test]
        public async Task RecaptchaGetOnValidationEndpoint_WithExceededLoginFailures_ShouldContainExpectedCssInRecaptchaBody()
        {
            using (var server = new IdentityServerWithRecaptchaValidationEndpoint()
                .WithProtectedGrantType("password")
                .WithPublicKey("recaptcha-public-key")
                .WithFailuresForIpAddress("192.168.1.101", NumberOfAllowedLoginFailures)
                .WithRecaptchaValidationEndpoint("/recaptcha/validation")
                .WithPublicKey("recaptcha-public-key")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(NumberOfAllowedLoginFailures).Build())
            {
                var response = await server.CreateRequest("/recaptcha/validation")
                    .AddHeader("HTTP_X_FORWARDED_FOR", "192.168.1.101")
                    .GetAsync();
                response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
                var resource = await response.Content.ReadAsAsync<IdentityServerUnauthorizedChallengeResource>();
                resource.LinkToChallenge.Should().Be("/recaptcha/platform");
                resource.Description.Should().Contain("add the x-recaptcha-answer");
                resource.ChallengeHtml.Should().Contain("<script src=\"https://www.google.com/recaptcha/api.js?hl=en-GB\" async defer>");
                resource.ChallengeHtml.Should().Contain("<div class=\"g-recaptcha\" data-sitekey=\"recaptcha-public-key\"></div>");
            }
        }

        [Test]
        public async Task RecaptchaGetOnValidationEndpoint_WithFailuresBelowThreshold_ShouldReturnSuccessNoContent()
        {
            using (var server = new IdentityServerWithRecaptchaValidationEndpoint()
                .WithProtectedGrantType("password")
                .WithPublicKey("recaptcha-public-key")
                .WithRecaptchaValidationEndpoint("/recaptcha/validation")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(NumberOfAllowedLoginFailures).Build())
            {
                var response = await server.CreateRequest("/recaptcha/validation")
                    .AddHeader("HTTP_X_FORWARDED_FOR", "192.168.1.101")
                    .GetAsync();
                response.StatusCode.Should().Be(HttpStatusCode.NoContent);
            }
        }
    }
}
