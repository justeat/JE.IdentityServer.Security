using System.Collections.Generic;
using System.Net;
using FluentAssertions;
using JE.IdentityServer.Security.OpenIdConnect;
using Microsoft.Owin;
using NUnit.Framework;

namespace JE.IdentityServer.Security.Tests.Extensions
{
    public class ExcludingRequestsBasedOnOptions
    {
        [Test]
        public void IsExcluded_WithNoUsername_ShouldReturnFalse()
        {
            var openIdConnectRequest = new OpenIdConnectRequest(IPAddress.None, string.Empty, null,
                new FormCollection(new Dictionary<string, string[]> { { "username", new[] { string.Empty } } }));
            new StubOpenIdConnectRequestOptions().IsExcluded(openIdConnectRequest).Should().BeFalse();
        }

        [Test]
        public void IsExcluded_WithUsernameSet_ShouldReturnTrue()
        {
            var openIdConnectRequest = new OpenIdConnectRequest(IPAddress.None, string.Empty, null,
                new FormCollection(new Dictionary<string, string[]> { { "username", new[] { "je.example.com" } } }));
            new StubOpenIdConnectRequestOptions().IsExcluded(openIdConnectRequest).Should().BeTrue();
        }

        [Test]
        public void IsExcluded_WithIpAddressWithinExcludedSubnet_ShouldReturnTrue()
        {
            var openIdConnectRequest = new OpenIdConnectRequest(IPAddress.Parse("192.168.100.29"), string.Empty, null,
                new FormCollection(new Dictionary<string, string[]> { { "username", new[] { "je.acme.com" } } }));
            new StubOpenIdConnectRequestOptions().IsExcluded(openIdConnectRequest).Should().BeTrue();
        }

        [Test]
        public void IsExcluded_WithIpAddressNotWithinExcludedSubnet_ShouldReturnFalse()
        {
            var openIdConnectRequest = new OpenIdConnectRequest(IPAddress.Parse("192.168.1.29"), string.Empty, null,
                new FormCollection(new Dictionary<string, string[]> { { "username", new[] { "je.acme.com" } } }));
            new StubOpenIdConnectRequestOptions().IsExcluded(openIdConnectRequest).Should().BeFalse();
        }
    }
}
