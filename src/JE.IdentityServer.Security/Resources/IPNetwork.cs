using System;
using System.Net;

namespace JE.IdentityServer.Security.Resources
{
    public class IPNetwork
    {
        private byte[] _address;
        private int _prefixLength;

        public IPNetwork(string value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            ParseCidrValue(value);
        }

        private void ParseCidrValue(string value)
        {
            var parts = value.Split('/');
            if (parts.Length != 2)
                throw new ArgumentException("Invalid CIDR notation", nameof(value));

            _address = IPAddress.Parse(parts[0]).GetAddressBytes();
            _prefixLength = Convert.ToInt32(parts[1], 10);
        }

        public bool Contains(IPAddress address)
        {
            return Contains(address.GetAddressBytes());
        }

        public bool Contains(byte[] address)
        {
            if (address == null)
            {
                throw new ArgumentNullException(nameof(address));
            }

            if (address.Length != _address.Length)
            {
                return false; // IPv4/IPv6 mismatch
            }

            var index = 0;
            var bits = _prefixLength;

            for (; bits >= 8; bits -= 8)
            {
                if (address[index] != _address[index])
                    return false;
                ++index;
            }

            if (bits <= 0) return true;

            int mask = (byte)~(255 >> bits);
            return (address[index] & mask) == (_address[index] & mask);
        }
    }
}