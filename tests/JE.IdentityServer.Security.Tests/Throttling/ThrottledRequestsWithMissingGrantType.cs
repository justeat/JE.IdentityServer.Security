using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using FluentAssertions;
using JE.IdentityServer.Security.Tests.Infrastructure;
using NUnit.Framework;

namespace JE.IdentityServer.Security.Tests.Throttling
{
    public class ThrottledRequestsWithMissingGrantType
    {
        [Test]
        public async Task ThrottledRequestsWithMissingGrantType_WithZeroAllowedFailures_ShouldAllowLogins()
        {
            using (var server = new IdentityServerWithThrottledLoginRequests()
                .WithNumberOfAllowedLoginFailures(0).Build())
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
        public async Task ThrottledRequestsWithMssingGrantType_WithZeroAllowedFailures_ShouldNotPublishLoginStatistics()
        {
            using (var identityServerWithThrottledLoginRequests = new IdentityServerWithThrottledLoginRequests()
                                                                    .WithNumberOfAllowedLoginFailures(0))
            {
                var server = identityServerWithThrottledLoginRequests.Build();
                var response = await server.CreateNativeLoginRequest()
                    .WithUsername("jeuser")
                    .WithPassword("Passw0rd")
                    .Build()
                    .PostAsync();
                response.StatusCode.Should().Be(HttpStatusCode.OK);
                var loginStatistics = identityServerWithThrottledLoginRequests.LoginStatistics;
                loginStatistics.TotalNumberOfFailedLogins.Should().Be(0);
                loginStatistics.TotalNumberOfSuccessfulLogins.Should().Be(0);
                loginStatistics.TotalNumberOfExcludedAttemptedLogins.Should().Be(0);
            }
        }

        [Test]
        public async Task ThrottledRequestsWithMissingGrantType_WithZeroAllowedFailures_ShouldFailOnLoginFailures()
        {
            using (var server = new IdentityServerWithThrottledLoginRequests()
                .WithNumberOfAllowedLoginFailures(0).Build())
            {
                var response = await server.CreateNativeLoginRequest()
                    .WithUsername("jeuser")
                    .WithPassword("Passw0rd123")
                    .Build()
                    .PostAsync();
                response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
                var tokenFailureResponse = await response.Content.ReadAsAsync<TokenFailureResponseModel>();
                tokenFailureResponse.Error.Should().Be("invalid_grant");
            }
        }
    }
}