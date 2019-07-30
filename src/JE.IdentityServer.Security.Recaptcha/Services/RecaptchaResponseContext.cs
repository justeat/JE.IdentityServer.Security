using System;

namespace JE.IdentityServer.Security.Recaptcha.Services
{
    public class RecaptchaResponseContext
    {
        public  RecaptchaState State { get; set; }
        public string Hostname { get; set; }
        public DateTime Timestamp { get; set; }
    }
}
