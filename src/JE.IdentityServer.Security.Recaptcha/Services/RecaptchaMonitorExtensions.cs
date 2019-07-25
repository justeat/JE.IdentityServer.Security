using JE.IdentityServer.Security.OpenIdConnect;

namespace JE.IdentityServer.Security.Recaptcha.Services
{
    public static class RecaptchaMonitorExtensions
    {
        public static RecaptchaUserContext ToRecaptchaUserContext(this IOpenIdConnectRequest request)
        {
            var device = request.GetDevice();

            return new RecaptchaUserContext
            {
                Username = request.GetUsername(),
                Device = new RecaptchaUserDevice
                {
                    Id = device?.DeviceId,
                    Name = device?.DeviceName,
                    Token = device?.DeviceToken,
                    Type = device?.DeviceType
                },
                IpAddress = request.GetRemoteIpAddress().ToString(),
                Tenant = request.GetTenant()
            };
        }
    }
}
