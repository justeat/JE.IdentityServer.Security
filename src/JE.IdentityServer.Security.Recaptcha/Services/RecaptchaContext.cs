using System;

namespace JE.IdentityServer.Security.Recaptcha.Services
{
    internal class RecaptchaContext : IRecaptchaContext
    {
        public RecaptchaContext(RecaptchaState challengeSucceeded, string hostname, DateTime timestamp)
        {
            State = challengeSucceeded;
            Hostname = hostname;
            Timestamp = timestamp;
        }

        public RecaptchaState State { get; }
        public string Hostname { get; }
        public DateTime Timestamp { get; }
    }
}
