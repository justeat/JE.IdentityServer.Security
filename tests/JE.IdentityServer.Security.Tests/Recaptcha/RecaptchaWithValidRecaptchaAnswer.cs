using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using FluentAssertions;
using JE.IdentityServer.Security.Recaptcha.Services;
using JE.IdentityServer.Security.Tests.Infrastructure;
using JustFakeIt;
using Newtonsoft.Json;
using NUnit.Framework;

namespace JE.IdentityServer.Security.Tests.Recaptcha
{
    public class RecaptchaWithValidRecaptchaAnswer
    {
        [Test]
        public async Task RecaptchaWithValidRecaptchaAnswer_WithAnswerAsBase64HeaderValue_ShouldNotChallenge()
        {
            using (var fakeRecaptchaServer = new FakeServer())
            {
                fakeRecaptchaServer.Start();
                fakeRecaptchaServer.Expect.Get("/?secret=private_key&response=correct_response")
                    .Returns(HttpStatusCode.OK, JsonConvert.SerializeObject(new RecaptchaVerificationResponse
                    {
                        Succeeded = true
                    }));

                using (var server = new IdentityServerWithRecaptcha()
                    .WithProtectedGrantType("password")
                    .WithPrivateKey("private_key")
                    .WithVerificationUri(fakeRecaptchaServer.BaseUri)
                    .WithNumberOfAllowedLoginFailuresPerIpAddress(1).Build())
                {
                    var response = await server.CreateNativeLoginRequest()
                        .WithUsername("jeuser")
                        .WithPassword("Passw0rd")
                        .WithHttpHeaderRecaptchaResponseBase64("correct_response")
                        .Build()
                        .PostAsync();
                    response.StatusCode.Should().Be(HttpStatusCode.OK);
                    var tokenResponse = await response.Content.ReadAsAsync<TokenResponseModel>();
                    tokenResponse.AccessToken.Should().NotBeNullOrEmpty();
                }
            }
        }

        [Test]
        public async Task RecaptchaWithValidRecaptchaAnswer_WithAnswerAsRawHeaderValue_ShouldNotChallenge()
        {
            using (var fakeRecaptchaServer = new FakeServer())
            {
                fakeRecaptchaServer.Start();
                fakeRecaptchaServer.Expect.Get("/?secret=private_key&response=correct_response")
                    .Returns(HttpStatusCode.OK, JsonConvert.SerializeObject(new RecaptchaVerificationResponse
                    {
                        Succeeded = true
                    }));

                using (var server = new IdentityServerWithRecaptcha()
                    .WithProtectedGrantType("password")
                    .WithPrivateKey("private_key")
                    .WithVerificationUri(fakeRecaptchaServer.BaseUri)
                    .WithNumberOfAllowedLoginFailuresPerIpAddress(1).Build())
                {
                    var response = await server.CreateNativeLoginRequest()
                        .WithUsername("jeuser")
                        .WithPassword("Passw0rd")
                        .WithHttpHeaderRecaptchaResponseRaw("correct_response")
                        .Build()
                        .PostAsync();
                    response.StatusCode.Should().Be(HttpStatusCode.OK);
                    var tokenResponse = await response.Content.ReadAsAsync<TokenResponseModel>();
                    tokenResponse.AccessToken.Should().NotBeNullOrEmpty();
                }
            }
        }

        [Test]
        public async Task RecaptchaWithValidRecaptchaAnswer_WithAnswerAsAcrValue_ShouldNotChallenge()
        {
            using (var fakeRecaptchaServer = new FakeServer())
            {
                fakeRecaptchaServer.Start();
                fakeRecaptchaServer.Expect.Get("/?secret=private_key&response=correct_response")
                    .Returns(HttpStatusCode.OK, JsonConvert.SerializeObject(new RecaptchaVerificationResponse
                    {
                        Succeeded = true
                    }));

                using (var server = new IdentityServerWithRecaptcha()
                    .WithProtectedGrantType("password")
                    .WithPrivateKey("private_key")
                    .WithVerificationUri(fakeRecaptchaServer.BaseUri)
                    .WithNumberOfAllowedLoginFailuresPerIpAddress(1).Build())
                {
                    var response = await server.CreateNativeLoginRequest()
                        .WithUsername("jeuser")
                        .WithPassword("Passw0rd")
                        .WithRecaptchaResponseAsAcrValue("correct_response")
                        .Build()
                        .PostAsync();
                    response.StatusCode.Should().Be(HttpStatusCode.OK);
                    var tokenResponse = await response.Content.ReadAsAsync<TokenResponseModel>();
                    tokenResponse.AccessToken.Should().NotBeNullOrEmpty();
                }
            }
        }

        [Test]
        public async Task RecaptchaWithValidCredentials_WhenEveryoneIsChallenged()
        {
            using (var fakeRecaptchaServer = new FakeServer())
            {
                fakeRecaptchaServer.Start();
                fakeRecaptchaServer.Expect.Get("/?secret=private_key&response=correct_response")
                    .Returns(HttpStatusCode.OK, JsonConvert.SerializeObject(new RecaptchaVerificationResponse
                    {
                        Succeeded = true
                    }));

                using (var server = new IdentityServerWithRecaptcha()
                    .WithProtectedGrantType("password")
                    .WithPrivateKey("private_key")
                    .WithVerificationUri(fakeRecaptchaServer.BaseUri)
                    .WithChallengeAsBadRequest()
                    .WithPlatformSecurityShieldsUp()
                    .Build())
                {
                    var response = await server.CreateNativeLoginRequest()
                        .WithUsername("jeuser")
                        .WithPassword("Passw0rd")
                        .WithGrantType("password")
                        .WithHttpHeaderRecaptchaResponseRaw("correct_response")
                        .Build()
                        .PostAsync();
                    response.StatusCode.Should().NotBe(HttpStatusCode.BadRequest);
                }
            }
        }

        [Test]
        public async Task RecaptchaWithValidCredentials_WithTooManyFailedLogins_ShouldPass()
        {
            const int NumberOfAllowedLoginFailures = 1;

            using (var fakeRecaptchaServer = new FakeServer())
            {
                fakeRecaptchaServer.Start();
                fakeRecaptchaServer.Expect.Get("/?secret=private_key&response=correct_response")
                    .Returns(HttpStatusCode.OK, JsonConvert.SerializeObject(new RecaptchaVerificationResponse
                    {
                        Succeeded = true
                    }));

                using (var server = new IdentityServerWithRecaptcha()
                    .WithProtectedGrantType("password")
                    .WithPrivateKey("private_key")
                    .WithVerificationUri(fakeRecaptchaServer.BaseUri)
                    .WithNumberOfAllowedLoginFailuresPerIpAddress(NumberOfAllowedLoginFailures)
                    .WithFailuresForIpAddress("192.168.1.101", NumberOfAllowedLoginFailures + 1)
                    .WithChallengeAsBadRequest()
                    .WithNumberOfAllowedLoginFailuresPerIpAddress(NumberOfAllowedLoginFailures).Build())
                {
                    var response = await server.CreateNativeLoginRequest()
                        .WithUsername("jeuser")
                        .WithPassword("Passw0rd")
                        .WithGrantType("password")
                        .WithHttpHeaderRecaptchaResponseRaw("correct_response")
                        .Build()
                        .PostAsync();
                    response.StatusCode.Should().NotBe(HttpStatusCode.BadRequest);
                }
            }
        }
    }
}