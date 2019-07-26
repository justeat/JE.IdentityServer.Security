using System.Threading.Tasks;
using JE.IdentityServer.Security.Recaptcha.Services;

namespace JE.IdentityServer.Security.Tests.Infrastructure
{
    public class RecaptchaMonitorStub : IRecaptchaMonitor
    {
        public RecaptchaState? RecaptchaState { get; private set; }
        public RecaptchaUserContext UserContext { get; private set; }
        public bool HasIssuedChallenge { get; private set; }
        public bool HasCompletedChallenge { get; private set; }

        public Task ChallengeIssued(RecaptchaUserContext userContext)
        {
            UserContext = userContext;
            HasIssuedChallenge = true;

            return Task.FromResult(true);
        }

        public Task ChallengeCompleted(RecaptchaUserContext userContext, RecaptchaState recaptchaState)
        {
            UserContext = userContext;
            RecaptchaState = recaptchaState;
            HasCompletedChallenge = true;

            return Task.FromResult(true);
        }

        public void Dispose() { }
    }
}
