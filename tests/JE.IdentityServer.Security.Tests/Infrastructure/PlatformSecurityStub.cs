using System.Threading.Tasks;
using JE.IdentityServer.Security.Services;

namespace JE.IdentityServer.Security.Tests.Infrastructure
{
    public class PlatformSecurityStub : IPlatformSecurity
    {
        private readonly bool _state;

        public PlatformSecurityStub(bool state)
        {
            _state = state;
        }

        public Task<bool> ShieldsAreUp()
        {
            return Task.FromResult(_state);
        }

        public void Dispose()
        {
        }
    }
}