using System;

namespace JE.IdentityServer.Security.Recaptcha.Services
{
    public interface IRecaptchaContext
    {
        RecaptchaState State { get; }
        string Hostname { get; }
        DateTime Timestamp { get; }
    }
}
