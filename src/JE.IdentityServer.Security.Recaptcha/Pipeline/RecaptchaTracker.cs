using System;

namespace JE.IdentityServer.Security.Recaptcha.Pipeline
{
    internal interface IRecaptchaTracker : IDisposable
    {
        bool IsCompleted { get; set; }
    }

    internal class RecaptchaTracker : IRecaptchaTracker
    {
        public bool IsCompleted { get; set; }

        public void Dispose() { }
    }
}
