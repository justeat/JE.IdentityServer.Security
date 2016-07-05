using System.Runtime.Serialization;

namespace JE.IdentityServer.Security.Resources
{
    [DataContract]
    public class IdentityServerBadRequestChallengeResource
    {
        [DataMember(Name = "Error")]
        public string Message { get; set; }

        [DataMember(Name = "Message")]
        public string Description { get; set; }

        [DataMember(Name = "ChallengeHtml")]
        public string ChallengeHtml { get; set; }
    }
}