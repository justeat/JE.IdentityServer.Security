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

                var identityServerBuilder = new IdentityServerWithRecaptcha()
                    .WithProtectedGrantType("password")
                    .WithPrivateKey("private_key")
                    .WithVerificationUri(fakeRecaptchaServer.BaseUri)
                    .WithNumberOfAllowedLoginFailuresPerIpAddress(1);

                using (var server = identityServerBuilder.Build())
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

                    identityServerBuilder.RecaptchaMonitor.HasIssuedChallenge.Should().BeFalse();
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

                var identityServerBuilder = new IdentityServerWithRecaptcha()
                    .WithProtectedGrantType("password")
                    .WithPrivateKey("private_key")
                    .WithVerificationUri(fakeRecaptchaServer.BaseUri)
                    .WithNumberOfAllowedLoginFailuresPerIpAddress(1);

                using (var server = identityServerBuilder.Build())
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

                    identityServerBuilder.RecaptchaMonitor.HasIssuedChallenge.Should().BeFalse();
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

                var identityServerBuilder = new IdentityServerWithRecaptcha()
                    .WithProtectedGrantType("password")
                    .WithPrivateKey("private_key")
                    .WithVerificationUri(fakeRecaptchaServer.BaseUri)
                    .WithNumberOfAllowedLoginFailuresPerIpAddress(1);

                using (var server = identityServerBuilder.Build())
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

                    identityServerBuilder.RecaptchaMonitor.HasIssuedChallenge.Should().BeFalse();
                }
            }
        }

        [Test]
        public async Task RecaptchaWithValidRecaptchaAnswer_WithLongAnswerAsAcrValue_ShouldNotChallenge()
        {
            const string longAnswer = "sHPqR2vXe1Gvena4WLtGvpslvmQjQrrFVTQDUpTPJ05IAsEpxeuGuuWI4bpOE0fqVgk3GGSjZS3ZbAPwXJhpeZuEaQhg6Vyp8PqYKD1906snU6aWgphMtSpo4QLOgyzRbAtGV6km58lBWKvrzrzEzYUerm44QXngw0meLTmryh33X0xHMzTSm7DGueATSlSO2lCv9E9xKomDpOZVp8tDYEL5bJflNvB3fMD2P2kUftlb8iv6VON6flwMLYrCuweFPQZ61FizEJGwJ4zpS1Mfgw5hV9BEkHhYbmuYBoLniKkB4KwPrYOHFw9IwFyKTiqIQC70RVWODc4hpjVsLsP4xeNuIASjDKj33Np4XiocvEYv8JIYTWuEffot0SKWVE8OgNQH5BL77FkLjERV";

            using (var fakeRecaptchaServer = new FakeServer())
            {
                fakeRecaptchaServer.Start();
                fakeRecaptchaServer.Expect.Get("/?secret=private_key&response=" + longAnswer)
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
                        .WithRecaptchaResponseAsAcrValue(longAnswer)
                        .Build()
                        .PostAsync();
                    response.StatusCode.Should().Be(HttpStatusCode.OK);
                    var tokenResponse = await response.Content.ReadAsAsync<TokenResponseModel>();
                    tokenResponse.AccessToken.Should().NotBeNullOrEmpty();
                }
            }
        }

        [Test]
        public async Task RecaptchaWithValidRecaptchaAnswer_WithLongAnswerAsAcrValue_AndAllTheTrimmings_ShouldNotChallenge()
        {
            const string longAnswer = "03ACgFB9vknGtsjy3YCRubfh4Nk4_9j4jIaJ8q5nPO6AOu391yoMxeQctcw6-OPt5HyBGjm8B25-xrQUDD-kQjoJOrY3IBiFa5fh__YC9RVbRTPxNrGdhdUjyJxVzQE5obPE1AUPScn3gyS6iaIOxgW_wB-ttxB-0_ybk7GP6Dz-QFnrXQaYYGZEEQxLHQReku_wwiOIWV40HFEpMx_Z-LwPBKOWO3fk2p3fQsnZGCcAhnszi6DfdYJWKdBmfra6BjcJ4Tfx2Xvyn75a4CmDwS7FYp6kg_dmzN1BaLPSA26DKndbrjL3lW2ghKsaat6TTcIx23M5jvcUlzsh5QxHWd3YhmmokS_QfZa0dyuWMUJ1TisYrVOGsg6p2tCiPIm5qLLaWl1scXMgA5PLBR3cx0fNy7Q72gbkfLOQ";

            using (var fakeRecaptchaServer = new FakeServer())
            {
                fakeRecaptchaServer.Start();
                fakeRecaptchaServer.Expect.Get("/?secret=private_key&response=" + longAnswer)
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
                        .WithRecaptchaResponseAsAcrValue(longAnswer)
                        .WithEncodedDevice("id", "type", "name", "token")
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

                var username = "jeuser";

                var identityServerBuilder = new IdentityServerWithRecaptcha()
                    .WithProtectedGrantType("password")
                    .WithPrivateKey("private_key")
                    .WithVerificationUri(fakeRecaptchaServer.BaseUri)
                    .WithChallengeAsBadRequest()
                    .WithPlatformSecurityShieldsUp();

                using (var server = identityServerBuilder.Build())
                {
                    var response = await server.CreateNativeLoginRequest()
                        .WithUsername(username)
                        .WithPassword("Passw0rd")
                        .WithGrantType("password")
                        .WithHttpHeaderRecaptchaResponseRaw("correct_response")
                        .Build()
                        .PostAsync();
                    response.StatusCode.Should().NotBe(HttpStatusCode.BadRequest);

                    identityServerBuilder.RecaptchaMonitor.HasCompletedChallenge.Should().BeTrue();
                    identityServerBuilder.RecaptchaMonitor.RecaptchaState.Should().Be(RecaptchaState.ChallengeSucceeded);
                    identityServerBuilder.RecaptchaMonitor.UserContext.Username.Should().Be(username);
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

                var ipAddress = "192.168.1.101";
                var username = "jeuser";

                var identityServerBuilder = new IdentityServerWithRecaptcha()
                    .WithProtectedGrantType("password")
                    .WithPrivateKey("private_key")
                    .WithVerificationUri(fakeRecaptchaServer.BaseUri)
                    .WithNumberOfAllowedLoginFailuresPerIpAddress(NumberOfAllowedLoginFailures)
                    .WithFailuresForIpAddress(ipAddress, NumberOfAllowedLoginFailures + 1)
                    .WithChallengeAsBadRequest()
                    .WithNumberOfAllowedLoginFailuresPerIpAddress(NumberOfAllowedLoginFailures);

                using (var server = identityServerBuilder.Build())
                {
                    var response = await server.CreateNativeLoginRequest()
                        .WithUsername(username)
                        .WithPassword("Passw0rd")
                        .WithGrantType("password")
                        .WithHttpHeaderRecaptchaResponseRaw("correct_response")
                        .Build()
                        .PostAsync();
                    response.StatusCode.Should().NotBe(HttpStatusCode.BadRequest);

                    identityServerBuilder.RecaptchaMonitor.HasCompletedChallenge.Should().BeTrue();
                    identityServerBuilder.RecaptchaMonitor.RecaptchaState.Should().Be(RecaptchaState.ChallengeSucceeded);
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
}
