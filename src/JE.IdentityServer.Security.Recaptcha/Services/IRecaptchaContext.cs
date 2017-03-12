namespace JE.IdentityServer.Security.Recaptcha.Services
{
    public interface IRecaptchaContext
    {
        RecaptchaState State { get; }
    }
}