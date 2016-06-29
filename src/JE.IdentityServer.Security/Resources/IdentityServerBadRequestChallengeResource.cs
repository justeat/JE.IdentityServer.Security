using System.Runtime.Serialization;

namespace JE.IdentityServer.Security.Resources
{
    /*
     * Challenge and ChallengeHtml are the same at the moment.
     * Challenge will be dropped in the next release. 
     */
    [DataContract]
    public class IdentityServerBadRequestChallengeResource
    {
        [DataMember(Name = "Error")]
        public string Message { get; set; }

        [DataMember(Name = "Message")]
        public string Description { get; set; }

        [DataMember(Name = "ChallengeHtml")]
        public string ChallengeHtml { get; set; }
        
        [DataMember(Name = "Challenge")]
        public string Challenge { get; set; }
    }
}