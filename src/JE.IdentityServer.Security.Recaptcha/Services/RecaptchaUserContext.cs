namespace JE.IdentityServer.Security.Recaptcha.Services
{
    public class RecaptchaUserContext
    {
        public string Username { get; set; }
        public string IpAddress { get; set; }
        public string UserAgent { get; set; }
        public RecaptchaUserDevice Device { get; set; }
        public string Tenant { get; set; }
    }
}
