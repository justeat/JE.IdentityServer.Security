using IdentityServer3.Core.Configuration;

namespace JE.IdentityServer.Security.Tests.Infrastructure
{
    public class NoDataProtector : IDataProtector
    {
        public byte[] Protect(byte[] data, string entropy = null)
        {
            return data;
        }

        public byte[] Unprotect(byte[] data, string entropy = null)
        {
            return data;
        }
    }
}