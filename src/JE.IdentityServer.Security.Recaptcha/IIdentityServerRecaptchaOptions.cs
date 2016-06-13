using System;

namespace JE.IdentityServer.Security.Recaptcha
{
    public interface IIdentityServerRecaptchaOptions
    {
        string PublicKey { get; }

        string PrivateKey { get; }

        Uri VerifyUri { get; }

        string LinkToChallenge { get; }

        string ContentServerName { get; }

        bool SupportBrowsersWithoutJavaScript { get; }
    }
}