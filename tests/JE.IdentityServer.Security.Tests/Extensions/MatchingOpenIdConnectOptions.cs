using System.Collections.Generic;
using System.Net;
using FluentAssertions;
using JE.IdentityServer.Security.OpenIdConnect;
using Microsoft.Owin;
using NUnit.Framework;

namespace JE.IdentityServer.Security.Tests.Extensions
{
    public class MatchingOpenIdConnectOptions
    {
        [Test]
        public void Match_WithNoGrantTypeSet_ShouldReturnFalse()
        {
            var openIdConnectRequest = new OpenIdConnectRequest(IPAddress.None, string.Empty, null, 
                new FormCollection(new Dictionary<string, string[]> {{ "grant_type", new [] { string.Empty }}}));
            new StubOpenIdConnectRequestOptions().Matches(openIdConnectRequest).Should().BeFalse();
        }

        [Test]
        public void Match_WithGrantTypeSetButUnrecognizedPath_ShouldReturnFalse()
        {
            var openIdConnectRequest = new OpenIdConnectRequest(IPAddress.None, "identity/token", null,
                new FormCollection(new Dictionary<string, string[]> { { "grant_type", new[] { "password" } } }));
            new StubOpenIdConnectRequestOptions().Matches(openIdConnectRequest).Should().BeFalse();
        }

        [Test]
        public void Match_WithGrantTypeAndPathSet_ShouldReturnTrue()
        {
            var openIdConnectRequest = new OpenIdConnectRequest(IPAddress.None, "identity/connect/token", null,
                new FormCollection(new Dictionary<string, string[]> { { "grant_type", new[] { "password" } } }));
            new StubOpenIdConnectRequestOptions().Matches(openIdConnectRequest).Should().BeTrue();
        }
    }
}
