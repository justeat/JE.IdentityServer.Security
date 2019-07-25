using System;
using System.Collections.Generic;
using System.Net;
using System.Text.RegularExpressions;
using JE.IdentityServer.Security.Recaptcha.Services;
using JE.IdentityServer.Security.Resolver;
using JE.IdentityServer.Security.Services;
using JE.IdentityServer.Security.Throttling;
using Microsoft.Owin.Testing;

namespace JE.IdentityServer.Security.Tests.Infrastructure
{
    public class IdentityServerWithThrottledLoginRequests : IDisposable
    {
        private string _protectedPath = "/identity/connect/token";
        private int _numberOfAllowedLoginFailures;

        private Regex _excludedUsernameExpression;
        private Regex _excludedTenantExpression;
        private Regex _excludedOsVersionExpression;

        private readonly IList<string> _protectedGrantTypes = new List<string>();
        private TestServer _testServer;
        private HttpStatusCode _throttledHttpStatusCode = (HttpStatusCode) 429;

        public LoginStatisticsStub LoginStatistics { get; } = new LoginStatisticsStub();
        public RecaptchaMonitorStub RecaptchaMonitor { get; } = new RecaptchaMonitorStub();

        public IdentityServerWithThrottledLoginRequests WithProtectedPath(string protectedPath)
        {
            _protectedPath = protectedPath;
            return this;
        }

        public IdentityServerWithThrottledLoginRequests WithNumberOfAllowedLoginFailures(int numberOfAllowedLoginFailures)
        {
            _numberOfAllowedLoginFailures = numberOfAllowedLoginFailures;
            return this;
        }

        public IdentityServerWithThrottledLoginRequests WithProtectedGrantType(string protectedGrantType)
        {
            _protectedGrantTypes.Add(protectedGrantType);
            return this;
        }

        public IdentityServerWithThrottledLoginRequests WithRequestsThrottledAsBadRequest()
        {
            _throttledHttpStatusCode = HttpStatusCode.BadRequest;
            return this;
        }

        public IdentityServerWithThrottledLoginRequests WithExcludedUsernameExpression(string excludedUsernameExpression)
        {
            _excludedUsernameExpression = new Regex(excludedUsernameExpression);
            return this;
        }

        public IdentityServerWithThrottledLoginRequests WithExcludedOsVersionExpression(string excludedOsVersionExpression)
        {
            _excludedOsVersionExpression = new Regex(excludedOsVersionExpression);
            return this;
        }

        public IdentityServerWithThrottledLoginRequests WithExcludedTenantExpression(string tenant)
        {
            _excludedTenantExpression = new Regex(tenant);
            return this;
        }

        public TestServer Build()
        {
            _testServer = TestServer.Create(app =>
            {
                app.UsePerOwinContext<ILoginStatistics>(() => LoginStatistics);
                app.UsePerOwinContext<IRecaptchaMonitor>(() => RecaptchaMonitor);
                app.UseThrottlingForAuthenticationRequests(new IdentityServerThrottlingOptions
                {
                    ProtectedPath = _protectedPath,
                    NumberOfAllowedLoginFailures = _numberOfAllowedLoginFailures,
                    ExcludedUsernameExpression = _excludedUsernameExpression,
                    ExcludedTenantExpression = _excludedTenantExpression,
                    ExcludedOsVersionExpression = _excludedOsVersionExpression,
                    ProtectedGrantTypes = _protectedGrantTypes,
                    HttpRequestThrottledStatusCode = _throttledHttpStatusCode
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
