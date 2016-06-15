using System;
using System.Collections.Generic;
using System.Net;
using JE.IdentityServer.Security.Resources;

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

        IEnumerable<IOpenIdConnectClient> WebClients { get; }

        HttpStatusCode HttpChallengeStatusCode { get; }
    }
}