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
        public async Task RecaptchaWithValidRecaptchaAnswer_WithAnswerAsHeaderValue_ShouldNotChallenge()
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
                        .WithHttpHeaderRecaptchaResponse("correct_response")
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
    }
}