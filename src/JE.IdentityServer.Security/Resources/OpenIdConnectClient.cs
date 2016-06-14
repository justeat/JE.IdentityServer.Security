namespace JE.IdentityServer.Security.Resources
{
    public class OpenIdConnectClient : IOpenIdConnectClient
    {
        public OpenIdConnectClient(string clientId, string secret)
        {
            ClientId = clientId;
            Secret = secret;
        }

        public string ClientId { get; }

        public string Secret { get; }
    }
}