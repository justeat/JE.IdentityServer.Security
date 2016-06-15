using System;
using System.Threading.Tasks;

namespace JE.IdentityServer.Security.Services
{
    public interface IPlatformSecurity : IDisposable
    {
        Task<bool> ShieldsAreUp();
    }
}