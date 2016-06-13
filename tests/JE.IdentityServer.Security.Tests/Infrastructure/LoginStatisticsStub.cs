using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using JE.IdentityServer.Security.Extensions;
using JE.IdentityServer.Security.Services;

namespace JE.IdentityServer.Security.Tests.Infrastructure
{
    public class LoginStatisticsStub : ILoginStatistics
    {
        private readonly IDictionary<string, int> _failedloginStatistics = new Dictionary<string, int>();
        private readonly IDictionary<long, int> _failedipAddressStatistics = new Dictionary<long, int>();
        private readonly IDictionary<string, int> _successfulLoginStatistics = new Dictionary<string, int>();
        private readonly IDictionary<string, int> _excludedAttemptedloginStatistics = new Dictionary<string, int>();
        
        public int TotalNumberOfFailedLogins => _failedloginStatistics.Values.Sum();
        public int TotalNumberOfSuccessfulLogins => _successfulLoginStatistics.Values.Sum();
        public int TotalNumberOfExcludedAttemptedLogins => _excludedAttemptedloginStatistics.Values.Sum();

        public Task<int> GetNumberOfFailedLoginsForUser(string username)
        {
            return Task.FromResult(_failedloginStatistics.ContainsKey(username)
                ? _failedloginStatistics[username] : 0);
        }

        public Task<int> GetNumberOfFailedLoginsForIpAddress(IPAddress remoteIpAddress)
        {
            var ipAddressAsInteger = remoteIpAddress.ToInteger();
            return Task.FromResult(_failedipAddressStatistics.ContainsKey(ipAddressAsInteger)
                ? _failedipAddressStatistics[ipAddressAsInteger] : 0);
        }

        public Task<int> GetNumberOfSucceededLoginsForUser(string username)
        {
            return Task.FromResult(_successfulLoginStatistics.ContainsKey(username)
                ? _successfulLoginStatistics[username] : 0);
        }

        public Task IncrementSuccessfulLoginsForUsernameAndIpAddress(string username, IPAddress ipAddress)
        {
            if (_successfulLoginStatistics.ContainsKey(username))
            {
                _successfulLoginStatistics[username] = _successfulLoginStatistics[username] + 1;
            }
            else
            {
                _successfulLoginStatistics[username] = 1;
            }

            return Task.Run(() => { });
        }

        public Task IncrementFailedLoginsForUserAndIpAddress(string username, IPAddress remoteIpAddress)
        {
            var ipAddress = remoteIpAddress.ToInteger();
            if (_failedloginStatistics.ContainsKey(username))
            {
                _failedloginStatistics[username] = _failedloginStatistics[username] + 1;
                _failedipAddressStatistics[ipAddress] = _failedipAddressStatistics[ipAddress] + 1;
            }
            else
            {
                _failedloginStatistics[username] = 1;
                _failedipAddressStatistics[ipAddress] = 1;
            }

            return Task.Run(() => { });
        }

        public Task IncrementAttemptedLoginsForExcludedUsernameAndIpAddress(string username, IPAddress remoteIpAddress)
        {
            if (_excludedAttemptedloginStatistics.ContainsKey(username))
            {
                _excludedAttemptedloginStatistics[username] = _excludedAttemptedloginStatistics[username] + 1;
            }
            else
            {
                _excludedAttemptedloginStatistics[username] = 1;
            }

            return Task.Run(() => { });
        }

        public void Dispose()
        {
            // NOOP
        }
    }
}