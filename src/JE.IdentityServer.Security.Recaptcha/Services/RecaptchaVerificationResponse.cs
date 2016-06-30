using System;
using System.Collections.Generic;
using Newtonsoft.Json;

namespace JE.IdentityServer.Security.Recaptcha.Services
{
    public sealed class RecaptchaVerificationResponse
    {
        [JsonProperty("success")]
        public bool Succeeded { get; set; }

        [JsonProperty("challenge_ts")]
        public DateTime Timestamp { get; set; }

        [JsonProperty("hostname")]
        public string Hostname { get; set; }

        [JsonProperty("error-codes")]
        public List<string> ErrorCodes { get; set; }
    }
}
