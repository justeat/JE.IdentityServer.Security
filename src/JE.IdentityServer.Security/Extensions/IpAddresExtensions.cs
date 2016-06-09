using System;
using System.Net;
using System.Net.Sockets;

namespace JE.IdentityServer.Security.Extensions
{
    public static class IpAddresExtensions
    {
        public static long ToInteger(this IPAddress ipAddress)
        {
            if (ipAddress == null)
            {
                return 0;
            }

            var bytes = ipAddress.GetAddressBytes();

            if (BitConverter.IsLittleEndian)
                Array.Reverse(bytes);

            return BitConverter.ToUInt32(bytes, 0);
        }

        public static bool IsValidIpAddress(this string ipAddress)
        {
            IPAddress resultingIpAddress;

            ipAddress = ipAddress?.Trim() ?? string.Empty;

            return ipAddress.Length != 0 && IPAddress.TryParse(ipAddress, out resultingIpAddress) 
                && (resultingIpAddress.AddressFamily == AddressFamily.InterNetwork || resultingIpAddress.AddressFamily == AddressFamily.InterNetworkV6);
        }
    }
}
