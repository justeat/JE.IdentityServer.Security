using System;
using System.Net;
using System.Threading.Tasks;

namespace JE.IdentityServer.Security.Services
{
    public interface ILoginStatistics : IDisposable
    {
        Task<int> GetNumberOfFailedLoginsForUser(string username);

        Task<int> GetNumberOfFailedLoginsForIpAddress(IPAddress getRemoteIpAddress);

        Task IncrementSuccessfulLoginsForUsernameAndIpAddress(string username, IPAddress ipAddress);

        Task IncrementFailedLoginsForUserAndIpAddress(string username, IPAddress ipAddress);

        Task IncrementAttemptedLoginsForExcludedUsernameAndIpAddress(string username, IPAddress ipAddress);
    }
}