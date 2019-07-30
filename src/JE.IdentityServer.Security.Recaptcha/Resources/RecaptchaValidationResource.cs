namespace JE.IdentityServer.Security.Recaptcha.Resources
{
    public class RecaptchaValidationResource
    {
        public string Device { get; set; }

        public string Sdk { get; set; }

        public string OsVersion { get; set; }

        public string Language { get; set; }

        public string Email { get; set; }

        public string Tenant { get; set; }
    }
}
