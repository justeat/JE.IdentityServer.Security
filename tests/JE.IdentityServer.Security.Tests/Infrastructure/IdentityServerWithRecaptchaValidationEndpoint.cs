using System;
using System.Collections.Generic;
using System.Net;
using JE.IdentityServer.Security.Recaptcha;
using JE.IdentityServer.Security.Resolver;
using JE.IdentityServer.Security.Resources;
using JE.IdentityServer.Security.Services;
using Microsoft.Owin.Testing;

namespace JE.IdentityServer.Security.Tests.Infrastructure
{
    public class IdentityServerWithRecaptchaValidationEndpoint : IDisposable
    {
        private string _protectedPath = "/identity/connect/token";
        private int _numberOfAllowedLoginFailuresPerIpAddress;
        private readonly IList<IPNetwork> _excludedSubnets = new List<IPNetwork>();
        private readonly IList<string> _protectedGrantTypes = new List<string>();
        private HttpStatusCode _challengeType = HttpStatusCode.Unauthorized;
        private TestServer _testServer;
        private Uri _verifyUri = new Uri("https://www.google.com/recaptcha/api/siteverify");
        private string _recaptchaPrivateKey;
        private string _recaptchaPublicKey;
        private string _contentServerName;
        private string _recaptchaValidationEndpoint;

        public LoginStatisticsStub LoginStatistics { get; } = new LoginStatisticsStub();

        public IdentityServerWithRecaptchaValidationEndpoint WithProtectedPath(string protectedPath)
        {
            _protectedPath = protectedPath;
            return this;
        }

        public IdentityServerWithRecaptchaValidationEndpoint WithRecaptchaValidationEndpoint(string recaptchaValidationEndpoint)
        {
            _recaptchaValidationEndpoint = recaptchaValidationEndpoint;
            return this;
        }

        public IdentityServerWithRecaptchaValidationEndpoint WithNumberOfAllowedLoginFailuresPerIpAddress(int numberOfAllowedLoginFailures)
        {
            _numberOfAllowedLoginFailuresPerIpAddress = numberOfAllowedLoginFailures;
            return this;
        }

        public IdentityServerWithRecaptchaValidationEndpoint WithProtectedGrantType(string protectedGrantType)
        {
            _protectedGrantTypes.Add(protectedGrantType);
            return this;
        }

        public IdentityServerWithRecaptchaValidationEndpoint WithExcludedSubnet(string excludedSubnet)
        {
            _excludedSubnets.Add(new IPNetwork(excludedSubnet));
            return this;
        }

        public IdentityServerWithRecaptchaValidationEndpoint WithChallengeAsBadRequest()
        {
            _challengeType = HttpStatusCode.BadRequest;
            return this;
        }

        public IdentityServerWithRecaptchaValidationEndpoint WithVerificationUri(Uri verifyUri)
        {
            _verifyUri = verifyUri;
            return this;
        }

        public IdentityServerWithRecaptchaValidationEndpoint WithPrivateKey(string privateKey)
        {
            _recaptchaPrivateKey = privateKey;
            return this;
        }

        public IdentityServerWithRecaptchaValidationEndpoint WithFailuresForIpAddress(string ipAddress, int numberOfFailures)
        {
            for (var failures = 0; failures < numberOfFailures; ++failures)
            {
                LoginStatistics.IncrementFailedLoginsForUserAndIpAddress(string.Empty, IPAddress.Parse(ipAddress));
            }
            return this;
        }

        public IdentityServerWithRecaptchaValidationEndpoint WithPublicKey(string recptchaPublicKey)
        {
            _recaptchaPublicKey = recptchaPublicKey;
            return this;
        }

        public IdentityServerWithRecaptchaValidationEndpoint WithContentServerName(string hostServer)
        {
            _contentServerName = hostServer;
            return this;
        }

        public TestServer Build()
        {
            const string linkToChallenge = "/recaptcha/platform";

            _testServer = TestServer.Create(app =>
            {
                app.UsePerOwinContext<ILoginStatistics>(() => LoginStatistics);
                app.UseRecaptchaForAuthenticationRequests(new IdentityServerRecaptchaOptions
                {
                    ProtectedPath = _protectedPath,
                    NumberOfAllowedLoginFailuresPerIpAddress = _numberOfAllowedLoginFailuresPerIpAddress,
                    ExcludedSubnets = _excludedSubnets,
                    ProtectedGrantTypes = _protectedGrantTypes,
                    HttpChallengeStatusCode = _challengeType,
                    LinkToChallenge = linkToChallenge,
                    VerifyUri = _verifyUri,
                    PrivateKey = _recaptchaPrivateKey,
                    PublicKey = _recaptchaPublicKey,
                    ContentServerName = _contentServerName
                });

                app.UseRecaptchaValidationEndpoint(new RecaptchaValidationOptions
                {
                    ProtectedPath = _recaptchaValidationEndpoint,
                    NumberOfAllowedLoginFailuresPerIpAddress = _numberOfAllowedLoginFailuresPerIpAddress,
                    ExcludedSubnets = _excludedSubnets,
                    HttpChallengeStatusCode = _challengeType,
                    LinkToChallenge = linkToChallenge,
                    VerifyUri = _verifyUri,
                    PrivateKey = _recaptchaPrivateKey,
                    PublicKey = _recaptchaPublicKey,
                    ContentServerName = _contentServerName,
                });

                app.UseInMemoryIdentityServer();
            });

            return _testServer;
        }

        public void Dispose()
        {
            _testServer?.Dispose();
        }
    }
}