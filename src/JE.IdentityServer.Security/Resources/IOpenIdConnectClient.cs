namespace JE.IdentityServer.Security.Resources
{
    public interface IOpenIdConnectClient
    {
        string ClientId { get; }

        string Secret { get; }
    }
}