using JE.IdentityServer.Security.OpenIdConnect;

namespace JE.IdentityServer.Security.Recaptcha.Services
{
    public static class RecaptchaMonitorExtensions
    {
        public static RecaptchaUserContext ToRecaptchaUserContext(this IOpenIdConnectRequest request)
        {
            if (request == null)
            {
                return new RecaptchaUserContext();
            }

            var device = request.GetDevice();

            return new RecaptchaUserContext
            {
                Username = request.GetUsername(),
                UserAgent = request.GetUserAgent(),
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

        public static RecaptchaResponseContext ToRecaptchaResponseContext(this IRecaptchaContext recaptchaContext)
        {
            return new RecaptchaResponseContext
            {
                Hostname = recaptchaContext.Hostname,
                State = recaptchaContext.State,
                Timestamp = recaptchaContext.Timestamp
            };
        }
    }
}
