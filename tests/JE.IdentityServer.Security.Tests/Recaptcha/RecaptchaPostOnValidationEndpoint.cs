using System.Net;
using System.Net.Http;
using System.Net.Http.Formatting;
using System.Threading.Tasks;
using FluentAssertions;
using JE.IdentityServer.Security.Recaptcha.Resources;
using JE.IdentityServer.Security.Resources;
using JE.IdentityServer.Security.Tests.Infrastructure;
using NUnit.Framework;

namespace JE.IdentityServer.Security.Tests.Recaptcha
{
    public class RecaptchaPostOnValidationEndpoint
    {
        private const int NumberOfAllowedLoginFailures = 1;

        [Test]
        public async Task RecaptchaPostOnValidationEndpoint_WithExcludedUsername_ShouldReturnNoContent()
        {
            using (var server = new IdentityServerWithRecaptchaValidationEndpoint()
                .WithProtectedGrantType("password")
                .WithExcludedUsernamesMatching("jeuser")
                .WithFailuresForIpAddress("192.168.1.101", NumberOfAllowedLoginFailures)
                .WithPublicKey("recaptcha-public-key")
                .WithRecaptchaValidationEndpoint("/recaptcha/validation")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(NumberOfAllowedLoginFailures).Build())
            {
                var response = await server.CreateRequest("/recaptcha/validation")
                    .AddHeader("HTTP_X_FORWARDED_FOR", "192.168.1.101")
                    .And(request =>
                    {
                        var recaptchaValidationResource = new RecaptchaValidationResource
                        { 
                            Tenant = "uk",
                            Email = "jeuser@mail.com"
                        };
                        request.Content = new ObjectContent(typeof(RecaptchaValidationResource),
                            recaptchaValidationResource, new JsonMediaTypeFormatter());
                    })
                    .PostAsync();
                response.StatusCode.Should().Be(HttpStatusCode.NoContent);
            }
        }

        [Test]
        public async Task RecaptchaPostOnValidationEndpoint_WithExcludedTenant_ShouldReturnNoContent()
        {
            using (var server = new IdentityServerWithRecaptchaValidationEndpoint()
                .WithProtectedGrantType("password")
                .WithExcludedTenantsMatching("uk")
                .WithFailuresForIpAddress("192.168.1.101", NumberOfAllowedLoginFailures)
                .WithPublicKey("recaptcha-public-key")
                .WithRecaptchaValidationEndpoint("/recaptcha/validation")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(NumberOfAllowedLoginFailures).Build())
            {
                var response = await server.CreateRequest("/recaptcha/validation")
                    .AddHeader("HTTP_X_FORWARDED_FOR", "192.168.1.101")
                    .And(request =>
                    {
                        var recaptchaValidationResource = new RecaptchaValidationResource
                        {
                            Tenant = "uk",
                            Email = "jeuser@mail.com"
                        };
                        request.Content = new ObjectContent(typeof(RecaptchaValidationResource),
                            recaptchaValidationResource, new JsonMediaTypeFormatter());
                    })
                    .PostAsync();
                response.StatusCode.Should().Be(HttpStatusCode.NoContent);
            }
        }

        [Test]
        public async Task RecaptchaPostOnValidationEndpoint_WithExcludedOsVersion_ShouldReturnNoContent()
        {
            using (var server = new IdentityServerWithRecaptchaValidationEndpoint()
                .WithProtectedGrantType("password")
                .WithExcludedOsVersionsMatching("5\\.0")
                .WithFailuresForIpAddress("192.168.1.101", NumberOfAllowedLoginFailures)
                .WithPublicKey("recaptcha-public-key")
                .WithRecaptchaValidationEndpoint("/recaptcha/validation")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(NumberOfAllowedLoginFailures).Build())
            {
                var response = await server.CreateRequest("/recaptcha/validation")
                    .AddHeader("HTTP_X_FORWARDED_FOR", "192.168.1.101")
                    .And(request =>
                    {
                        var recaptchaValidationResource = new RecaptchaValidationResource
                        {
                            Tenant = "uk",
                            Email = "jeuser@mail.com",
                            OsVersion = "5.0"
                        };
                        request.Content = new ObjectContent(typeof(RecaptchaValidationResource),
                            recaptchaValidationResource, new JsonMediaTypeFormatter());
                    })
                    .PostAsync();
                response.StatusCode.Should().Be(HttpStatusCode.NoContent);
            }
        }

        [Test]
        public async Task RecaptchaPostOnValidationEndpoint_WithExceededLoginFailures_ShouldReturnUnauthorized()
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
                    .And(request =>
                    {
                        var recaptchaValidationResource = new RecaptchaValidationResource
                        {
                            Tenant = "uk",
                            Email = "jeuser@mail.com",
                            OsVersion = "5.0"
                        };
                        request.Content = new ObjectContent(typeof(RecaptchaValidationResource),
                            recaptchaValidationResource, new JsonMediaTypeFormatter());
                    })
                    .PostAsync();
                response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
            }
        }

        [Test]
        public async Task RecaptchaPostOnValidationEndpoint_WithExceededLoginFailures_ShouldContainExpectedRecaptchaBody()
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
                    .And(request =>
                    {
                        var recaptchaValidationResource = new RecaptchaValidationResource
                        {
                            Tenant = "uk",
                            Email = "jeuser@mail.com",
                            OsVersion = "5.0",
                            Language = "es-ES"
                        };
                        request.Content = new ObjectContent(typeof(RecaptchaValidationResource),
                            recaptchaValidationResource, new JsonMediaTypeFormatter());
                    })
                    .PostAsync();
                var resource = await response.Content.ReadAsAsync<IdentityServerUnauthorizedChallengeResource>();
                resource.ChallengeHtml.Should().StartWith("<script src=\"https://www.google.com/recaptcha/api.js?hl=es-ES\"");
            }
        }

        [Test]
        public async Task RecaptchaPostOnValidationEndpoint_WithFailuresBelowThreshold_ShouldReturnSuccessNoContent()
        {
            using (var server = new IdentityServerWithRecaptchaValidationEndpoint()
                .WithProtectedGrantType("password")
                .WithPublicKey("recaptcha-public-key")
                .WithRecaptchaValidationEndpoint("/recaptcha/validation")
                .WithNumberOfAllowedLoginFailuresPerIpAddress(NumberOfAllowedLoginFailures).Build())
            {
                var response = await server.CreateRequest("/recaptcha/validation")
                    .AddHeader("HTTP_X_FORWARDED_FOR", "192.168.1.101")
                    .And(request =>
                    {
                        var recaptchaValidationResource = new RecaptchaValidationResource
                        {
                            Tenant = "uk",
                            Email = "jeuser@mail.com",
                            OsVersion = "5.0"
                        };
                        request.Content = new ObjectContent(typeof(RecaptchaValidationResource),
                            recaptchaValidationResource, new JsonMediaTypeFormatter());
                    })
                    .PostAsync();
                response.StatusCode.Should().Be(HttpStatusCode.NoContent);
            }
        }
    }
}