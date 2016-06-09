using System.Collections.Generic;

namespace JE.IdentityServer.Security.Recaptcha.Services
{
    public class RecaptchaVerificationResponse
    {
        public bool Succeeded { get; set; }
        public IEnumerable<string> ErrorCodes { get; set; }
    }
}