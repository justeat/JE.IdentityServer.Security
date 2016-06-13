using System.Linq;
using Microsoft.Owin;

namespace JE.IdentityServer.Security.Extensions
{
    public static class OwinContextIpAddressExtensions
    {
        // The order matters here!
        private static readonly HeaderItem[] RemoteClientIpHeaderKeys =
        {
            new HeaderItem("HTTP_CLIENT_IP", false),
            new HeaderItem("HTTP_X_FORWARDED_FOR", true),
            new HeaderItem("HTTP_X_FORWARDED", true),
            new HeaderItem("HTTP_X_CLUSTER_CLIENT_IP", false),
            new HeaderItem("HTTP_FORWARDED_FOR", true),
            new HeaderItem("HTTP_FORWARDED", true),
            new HeaderItem("HTTP_VIA", false),
            new HeaderItem("REMOTE_ADDR", false)
        };

        // https://en.wikipedia.org/wiki/X-Forwarded-For
        public static string GetRemoteClientIpAddress(this IOwinContext owinContext)
        {
            foreach (var item in RemoteClientIpHeaderKeys)
            {
                var ipAddress = owinContext.Request.Headers[item.Key];

                if (string.IsNullOrEmpty(ipAddress))
                {
                    continue;
                }

                if (item.Split) // Client should be the first one, but we don't care
                {
                    var ipAddressParts = ipAddress.Split(',');
                    foreach (var ipAddressPart in ipAddressParts.Where(ip => ip.IsValidIpAddress()))
                    {
                        return ipAddressPart;
                    }
                }

                if (ipAddress.IsValidIpAddress())
                {
                    return ipAddress;
                }
            }

            return owinContext.Request.RemoteIpAddress;
        }

        private sealed class HeaderItem
        {
            public readonly string Key;
            public readonly bool Split;

            public HeaderItem(string key, bool split)
            {
                Key = key;
                Split = split;
            }
        }
    }
}