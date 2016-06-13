namespace JE.IdentityServer.Security.Resources
{
    public class IdentityServerUnauthorizedChallengeResource
    {
        public string ChallengeHtml { get; set; }

        public string LinkToChallenge { get; set; }

        public string Description { get; set; }
    }
}