using Newtonsoft.Json;

namespace JE.IdentityServer.Security.Tests.Infrastructure
{
    public class TokenFailureResponseModel
    {
        [JsonProperty("error")]
        public string Error { get; set; }
    }
}