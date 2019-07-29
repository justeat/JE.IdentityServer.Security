using System.Threading.Tasks;
using JE.IdentityServer.Security.Recaptcha.Services;

namespace JE.IdentityServer.Security.Tests.Infrastructure
{
    public class RecaptchaMonitorStub : IRecaptchaMonitor
    {
        public RecaptchaUserContext UserContext { get; private set; }
        public RecaptchaResponseContext ResponseContext { get; private set; }
        public bool HasIssuedChallenge { get; private set; }
        public bool HasCompletedChallenge { get; private set; }

        public Task ChallengeIssued(RecaptchaUserContext userContext)
        {
            UserContext = userContext;
            HasIssuedChallenge = true;

            return Task.FromResult(true);
        }

        public Task ChallengeCompleted(RecaptchaUserContext userContext, RecaptchaResponseContext responseContext)
        {
            UserContext = userContext;
            ResponseContext = responseContext;
            HasCompletedChallenge = true;

            return Task.FromResult(true);
        }

        public void Dispose() { }
    }
}
