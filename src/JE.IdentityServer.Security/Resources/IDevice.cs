namespace JE.IdentityServer.Security.Resources
{
    public interface IDevice
    {
        string DeviceId { get; }
        string DeviceType { get; }
        string DeviceName { get; }
        string DeviceToken { get; }
    }
}