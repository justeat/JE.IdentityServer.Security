namespace JE.IdentityServer.Security.Recaptcha.Services
{
    internal class RecaptchaContext : IRecaptchaContext
    {
        public RecaptchaContext(RecaptchaState challengeSucceeded)
        {
            State = challengeSucceeded;
        }

        public RecaptchaState State { get; private set; }
    }
}