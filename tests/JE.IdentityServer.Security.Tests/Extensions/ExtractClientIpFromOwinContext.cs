using JE.IdentityServer.Security.Extensions;
using Microsoft.Owin;
using NUnit.Framework;

namespace JE.IdentityServer.Security.Tests.Extensions
{
    public class ExtractClientIpFromOwinContext
    {
        [TestCase("HTTP_CLIENT_IP", "192.168.100.1", ExpectedResult = "192.168.100.1")]
        [TestCase("HTTP_X_FORWARDED_FOR", "192.168.100.1", ExpectedResult = "192.168.100.1")]
        [TestCase("HTTP_X_FORWARDED", "192.168.100.1", ExpectedResult = "192.168.100.1")]
        [TestCase("HTTP_X_CLUSTER_CLIENT_IP", "192.168.100.1", ExpectedResult = "192.168.100.1")]
        [TestCase("HTTP_FORWARDED_FOR", "192.168.100.1", ExpectedResult = "192.168.100.1")]
        [TestCase("HTTP_FORWARDED", "192.168.100.1", ExpectedResult = "192.168.100.1")]
        [TestCase("HTTP_VIA", "192.168.100.1", ExpectedResult = "192.168.100.1")]
        [TestCase("REMOTE_ADDR", "192.168.100.1", ExpectedResult = "192.168.100.1")]
        [TestCase("REMOTE_ADDR-UNKNOWN", "192.168.100.1", ExpectedResult = "192.168.100.125")]

        [TestCase("HTTP_X_FORWARDED_FOR", "192.168.100.1, 192.168.200.101", ExpectedResult = "192.168.100.1")]
        [TestCase("HTTP_X_FORWARDED", "192.168.100.1, 192.168.200.101", ExpectedResult = "192.168.100.1")]
        [TestCase("HTTP_FORWARDED_FOR", "192.168.100.1, 192.168.200.101", ExpectedResult = "192.168.100.1")]
        [TestCase("HTTP_FORWARDED", "192.168.100.1, 192.168.200.101", ExpectedResult = "192.168.100.1")]
        public string GetRemoteClientIpAddress_WithProxyHeadersSet_ShouldReturnRemoteClientIpAddress(string header, string value)
        {
            var owinContext = new OwinContext { Request = { Headers = { { header, new[] { value } } }, RemoteIpAddress = "192.168.100.125" } };
            return owinContext.GetRemoteClientIpAddress();
        }
    }
}
