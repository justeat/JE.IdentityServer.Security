using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using FluentAssertions;
using JE.IdentityServer.Security.Resources;
using JE.IdentityServer.Security.Tests.Infrastructure;
using NUnit.Framework;

namespace JE.IdentityServer.Security.Tests.Throttling
{
    public class ThrottledRequestsWithMatchingGrantType
    {
        [Test]
        public async Task ThrottledRequests_WithZeroAllowedFailures_ShouldAllowLogins()
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
        public async Task ThrottledRequests_WithAllowedFailures_ShouldPublishSuccessfulLogins()
        {
            const int numberOfAllowedLoginFailures = 3;
            using (var identityServerWithThrottledLoginRequests = new IdentityServerWithThrottledLoginRequests()
                                                                        .WithNumberOfAllowedLoginFailures(numberOfAllowedLoginFailures)
                                                                        .WithProtectedGrantType("password"))
            {
                var server = identityServerWithThrottledLoginRequests.Build();
                for (var attempt = 0; attempt < numberOfAllowedLoginFailures; ++attempt)
                {
                    await server.CreateNativeLoginRequest()
                        .WithUsername("jeuser")
                        .WithPassword("Passw0rd")
                        .Build()
                        .PostAsync();
                }

                identityServerWithThrottledLoginRequests.LoginStatistics.TotalNumberOfSuccessfulLogins.Should()
                    .Be(numberOfAllowedLoginFailures);
            }
        }

        [Test]
        public async Task ThrottledRequests_WithAllowedFailuresAndDefaultResponse_ShouldThrottleRequestsAboveThreshold()
        {
            const int numberOfAllowedLoginFailures = 3;
            using (var server = new IdentityServerWithThrottledLoginRequests()
                                        .WithNumberOfAllowedLoginFailures(numberOfAllowedLoginFailures)
                                        .WithProtectedGrantType("password").Build())
            {
                const int numberOfFailedLoginAttemptsThatExceedThreshold = numberOfAllowedLoginFailures + 1;
                for (var attempt = 1; attempt <= numberOfFailedLoginAttemptsThatExceedThreshold; ++attempt)
                {
                    await server.CreateNativeLoginRequest()
                        .WithUsername("jeuser")
                        .WithPassword("Passw0rd123")
                        .Build()
                        .PostAsync();
                }

                var response = await server.CreateNativeLoginRequest()
                                           .WithUsername("jeuser")
                                           .WithPassword("Passw0rd123")
                                           .Build()
                                           .PostAsync();

                response.StatusCode.Should().Be((HttpStatusCode)429);
                var tokenResponse = await response.Content.ReadAsAsync<IdentityServerErrorResource>();
                tokenResponse.Message.Should().Be("Too many connections");
            }
        }

        [Test]
        public async Task ThrottledRequests_WithAllowedFailuresAndBadRequestResponse_ShouldThrottleRequestsAboveThreshold()
        {
            const int numberOfAllowedLoginFailures = 3;
            using (var server = new IdentityServerWithThrottledLoginRequests()
                                        .WithNumberOfAllowedLoginFailures(numberOfAllowedLoginFailures)
                                        .WithRequestsThrottledAsBadRequest()
                                        .WithProtectedGrantType("password").Build())
            {
                const int numberOfFailedLoginAttemptsThatExceedThreshold = numberOfAllowedLoginFailures + 1;
                for (var attempt = 1; attempt <= numberOfFailedLoginAttemptsThatExceedThreshold; ++attempt)
                {
                    await server.CreateNativeLoginRequest()
                        .WithUsername("jeuser")
                        .WithPassword("Passw0rd123")
                        .Build()
                        .PostAsync();
                }

                var response = await server.CreateNativeLoginRequest()
                                           .WithUsername("jeuser")
                                           .WithPassword("Passw0rd123")
                                           .Build()
                                           .PostAsync();

                response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
                var tokenResponse = await response.Content.ReadAsAsync<IdentityServerUnauthorizedChallengeResource>();
                tokenResponse.Description.Should().Be("Too many connections");
            }
        }

        [Test]
        public async Task ThrottledRequests_WithAllowedFailures_ShouldAllowFailuresBelowThreshold()
        {
            const int numberOfAllowedLoginFailures = 3;
            using (var server = new IdentityServerWithThrottledLoginRequests()
                                        .WithNumberOfAllowedLoginFailures(numberOfAllowedLoginFailures)
                                        .WithProtectedGrantType("password").Build())
            {
                for (var attempt = 1; attempt <= numberOfAllowedLoginFailures; ++attempt)
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

        [Test]
        public async Task ThrottledRequests_WithAllowedFailures_ShouldPublishLoginStatistics()
        {
            const int numberOfAllowedLoginFailures = 3;
            using (var identityServerWithThrottledLoginRequests = new IdentityServerWithThrottledLoginRequests()
                                                                        .WithNumberOfAllowedLoginFailures(numberOfAllowedLoginFailures)
                                                                        .WithProtectedGrantType("password"))
            {
                var server = identityServerWithThrottledLoginRequests.Build();
                for (var attempt = 1; attempt <= numberOfAllowedLoginFailures; ++attempt)
                {
                    await server.CreateNativeLoginRequest()
                        .WithUsername("jeuser")
                        .WithPassword("Passw0rd123")
                        .Build()
                        .PostAsync();
                }

                await server.CreateNativeLoginRequest()
                    .WithUsername("jeuser")
                    .WithPassword("Passw0rd123")
                    .Build()
                    .PostAsync();

                const int expectedNumberOfReportedLoginFailures = numberOfAllowedLoginFailures + 1;
                identityServerWithThrottledLoginRequests.LoginStatistics.TotalNumberOfFailedLogins.Should()
                    .Be(expectedNumberOfReportedLoginFailures);
                identityServerWithThrottledLoginRequests.LoginStatistics.TotalNumberOfSuccessfulLogins.Should()
                    .Be(0);
            }
        }

        [Test]
        public async Task ThrottledRequests_WithAllowedFailures_ShouldNotPublishExcludedLoginStatistics()
        {
            const int numberOfAllowedLoginFailures = 3;
            using (var identityServerWithThrottledLoginRequests = new IdentityServerWithThrottledLoginRequests()
                                                                        .WithNumberOfAllowedLoginFailures(numberOfAllowedLoginFailures)
                                                                        .WithProtectedGrantType("password"))
            {
                var server = identityServerWithThrottledLoginRequests.Build();
                for (var attempt = 1; attempt <= numberOfAllowedLoginFailures; ++attempt)
                {
                    await server.CreateNativeLoginRequest()
                        .WithUsername("jeuser")
                        .WithPassword("Passw0rd123")
                        .Build()
                        .PostAsync();
                }

                await server.CreateNativeLoginRequest()
                    .WithUsername("jeuser")
                    .WithPassword("Passw0rd123")
                    .Build()
                    .PostAsync();

                identityServerWithThrottledLoginRequests.LoginStatistics.TotalNumberOfExcludedAttemptedLogins.Should()
                    .Be(0);
            }
        }
    }
}
