using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace JE.IdentityServer.Security.Recaptcha.Services
{
    public class DefaultRecaptchaValidationService : IRecaptchaValidationService
    {
        public async Task<RecaptchaVerificationResponse> Validate(string recaptchaResponse, IdentityServerRecaptchaOptions options)
        {
            using (var client = new HttpClient())
            {
                var recaptchaValidationUri = string.Format(
                    options.VerifyUri + "?secret={0}&response={1}",
                    options.PrivateKey,
                    recaptchaResponse);

                var httpResponse = await client.GetAsync(recaptchaValidationUri);

                if (httpResponse.IsSuccessStatusCode)
                {
                    using (var responseStream = await httpResponse.Content.ReadAsStreamAsync())
                    {
                        using (var jsonStream = new StreamReader(responseStream))
                        {
                            var json = jsonStream.ReadToEnd();
                            return JsonConvert.DeserializeObject<RecaptchaVerificationResponse>(json);
                        }
                    }
                }

                var succeeded = httpResponse.StatusCode == HttpStatusCode.InternalServerError ||
                                httpResponse.StatusCode == HttpStatusCode.ServiceUnavailable;

                return new RecaptchaVerificationResponse
                {
                    Succeeded = succeeded
                };
            }
        }

        public void Dispose()
        {
            // NOOP
        }
    }
}
