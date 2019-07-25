using System;
using System.Threading.Tasks;

namespace JE.IdentityServer.Security.Recaptcha.Services
{
    public interface IRecaptchaMonitor : IDisposable
    {
        Task ChallengeIssued(RecaptchaUserContext userContext);
        Task ChallengeCompleted(RecaptchaState recaptchaState, RecaptchaUserContext userContext);
    }
}
