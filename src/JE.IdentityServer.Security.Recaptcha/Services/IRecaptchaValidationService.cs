using System;
using System.Threading.Tasks;

namespace JE.IdentityServer.Security.Recaptcha.Services
{
    public interface IRecaptchaValidationService : IDisposable
    {
        Task<RecaptchaVerificationResponse> Validate(string recaptchaResponse, IdentityServerRecaptchaOptions options);
    }
}
