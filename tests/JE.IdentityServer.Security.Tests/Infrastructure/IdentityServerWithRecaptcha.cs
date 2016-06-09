using System;
using System.Collections.Generic;
using System.Net;
using System.Text.RegularExpressions;
using JE.IdentityServer.Security.Recaptcha;
using JE.IdentityServer.Security.Resolver;
using JE.IdentityServer.Security.Resources;
using JE.IdentityServer.Security.Services;
using Microsoft.Owin.Testing;

namespace JE.IdentityServer.Security.Tests.Infrastructure
{
    public class IdentityServerWithRecaptcha : IDisposable
    {
        private string _protectedPath = "/identity/connect/token";
        private int _numberOfAllowedLoginFailuresPerIpAddress;
        private readonly IList<IPNetwork> _excludedSubnets = new List<IPNetwork>();
        private readonly IList<string> _protectedGrantTypes = new List<string>();
        private readonly IList<Regex> _exludedUsernameExpressions = new List<Regex>();
        private HttpStatusCode _challengeType = HttpStatusCode.Unauthorized;
        private TestServer _testServer;
        private Uri _verifyUri = new Uri("https://www.google.com/recaptcha/api/siteverify");
        private string _recaptchaPrivateKey;
        private string _recaptchaPublicKey;
        private string _contentServerName;

        public LoginStatisticsStub LoginStatistics { get; } = new LoginStatisticsStub();

        public IdentityServerWithRecaptcha WithProtectedPath(string protectedPath)
        {
            _protectedPath = protectedPath;
            return this;
        }

        public IdentityServerWithRecaptcha WithNumberOfAllowedLoginFailuresPerIpAddress(int numberOfAllowedLoginFailures)
        {
            _numberOfAllowedLoginFailuresPerIpAddress = numberOfAllowedLoginFailures;
            return this;
        }

        public IdentityServerWithRecaptcha WithProtectedGrantType(string protectedGrantType)
        {
            _protectedGrantTypes.Add(protectedGrantType);
            return this;
        }

        public IdentityServerWithRecaptcha WithExcludedSubnet(string excludedSubnet)
        {
            _excludedSubnets.Add(new IPNetwork(excludedSubnet));
            return this;
        }

        public IdentityServerWithRecaptcha WithChallengeAsBadRequest()
        {
            _challengeType = HttpStatusCode.BadRequest;
            return this;
        }

        public IdentityServerWithRecaptcha WithVerificationUri(Uri verifyUri)
        {
            _verifyUri = verifyUri;
            return this;
        }

        public IdentityServerWithRecaptcha WithPrivateKey(string privateKey)
        {
            _recaptchaPrivateKey = privateKey;
            return this;
        }

        public IdentityServerWithRecaptcha WithFailuresForIpAddress(string ipAddress, int numberOfFailures)
        {
            for (var failures = 0; failures < numberOfFailures; ++failures)
            {
                LoginStatistics.IncrementFailedLoginsForUserAndIpAddress(string.Empty, IPAddress.Parse(ipAddress));
            }
            return this;
        }

        public IdentityServerWithRecaptcha WithPublicKey(string recptchaPublicKey)
        {
            _recaptchaPublicKey = recptchaPublicKey;
            return this;
        }

        public IdentityServerWithRecaptcha WithExcludedUsernamesMatching(string usernameMatchString)
        {
            _exludedUsernameExpressions.Add(new Regex(usernameMatchString));
            return this;
        }

        public IdentityServerWithRecaptcha WithContentServerName(string hostServer)
        {
            _contentServerName = hostServer;
            return this;
        }

        public TestServer Build()
        {
            _testServer = TestServer.Create(app =>
            {
                app.UsePerOwinContext<ILoginStatistics>(() => LoginStatistics);
                app.UseRecaptchaForAuthenticationRequests(new IdentityServerRecaptchaOptions
                {
                    ProtectedPath = _protectedPath,
                    NumberOfAllowedLoginFailuresPerIpAddress = _numberOfAllowedLoginFailuresPerIpAddress,
                    ExcludedUsernameExpressions = _exludedUsernameExpressions,
                    ExcludedSubnets = _excludedSubnets,
                    ProtectedGrantTypes = _protectedGrantTypes,
                    HttpChallengeStatusCode = _challengeType,
                    LinkToChallenge = "/recaptcha/platform",
                    VerifyUri = _verifyUri,
                    PrivateKey = _recaptchaPrivateKey,
                    PublicKey = _recaptchaPublicKey,
                    ContentServerName = _contentServerName
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