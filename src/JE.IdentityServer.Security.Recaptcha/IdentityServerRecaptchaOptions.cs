using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using JE.IdentityServer.Security.OpenIdConnect;
using JE.IdentityServer.Security.Resources;

namespace JE.IdentityServer.Security.Recaptcha
{
    public class IdentityServerRecaptchaOptions : IOpenIdConnectRequestOptions, IIdentityServerRecaptchaOptions
    {

        public virtual string PublicKey { get; set; }

        public virtual string PrivateKey { get; set; }

        public virtual Uri VerifyUri { get; set; } = new Uri("https://www.google.com/recaptcha/api/siteverify");

        public virtual string LinkToChallenge { get; set; } = "/recaptcha.aspx";

        public virtual IEnumerable<string> WhiteListedEmailAddresses { get; set; } = Enumerable.Empty<string>();

        public virtual HttpStatusCode HttpChallengeStatusCode { get; set; } = HttpStatusCode.Unauthorized;

        public string ProtectedPath { get; set; }

        public virtual Regex ExcludedUsernameExpression { get; set; }

        public virtual Regex ExcludedTenantExpression { get; set; }

        public virtual Regex ExcludedOsVersionExpression { get; set; }

        public virtual Regex ExcludedDeviceExpression { get; set; }

        public virtual int NumberOfAllowedLoginFailuresPerIpAddress { get; set; }

        public virtual IEnumerable<string> ProtectedGrantTypes { get; set; }

        public virtual IEnumerable<IPNetwork> ExcludedSubnets { get; set; } = Enumerable.Empty<IPNetwork>();

        public virtual string ContentServerName { get; set; }

        public virtual bool SupportBrowsersWithoutJavaScript { get; set; }

        public virtual IEnumerable<IOpenIdConnectClient> WebClients { get; set; } = Enumerable.Empty<IOpenIdConnectClient>();
    }
}
