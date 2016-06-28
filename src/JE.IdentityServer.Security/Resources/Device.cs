namespace JE.IdentityServer.Security.Resources
{
    public class Device : IDevice
    {
        public Device(string deviceId, string deviceType, string deviceName, string deviceToken)
        {
            DeviceId = deviceId;
            DeviceType = deviceType;
            DeviceName = deviceName;
            DeviceToken = deviceToken;
        }

        public Device(string deviceType)
        {
            DeviceType = deviceType;
        }

        public Device()
        {
            // For json serialization/deserialization
        }

        public string DeviceId { get; set; }

        public string DeviceType { get; set; }

        public string DeviceName { get; set; }

        public string DeviceToken { get; set; }
    }
}