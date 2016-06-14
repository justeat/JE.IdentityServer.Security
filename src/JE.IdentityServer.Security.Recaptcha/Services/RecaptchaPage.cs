using System.Globalization;
using System.Linq;
using JE.IdentityServer.Security.OpenIdConnect;
using JE.IdentityServer.Security.Resources;

namespace JE.IdentityServer.Security.Recaptcha.Services
{
    public class RecaptchaPage : IRecaptchaPage
    {
        private readonly IIdentityServerRecaptchaOptions _options;
        private const string DefaultLanguageCode = "en-GB";

        public RecaptchaPage(IIdentityServerRecaptchaOptions options)
        {
            _options = options;
        }

        public string CreateHtmlBody(string languageCode, IDevice device)
        {
            if (string.IsNullOrEmpty(languageCode))
            {
                languageCode = DefaultLanguageCode;
            }

            return CreateFullHtmlBody(languageCode, device);
        }

        public string CreateHtmlBody(IOpenIdConnectRequest openIdConnectRequest)
        {
            var languageCode = openIdConnectRequest.GetLanguage();

            if (string.IsNullOrEmpty(languageCode))
            {
                languageCode = DefaultLanguageCode;
            }

            return _options.SupportsPartialRecaptcha(openIdConnectRequest) 
                ? CreatePartialHtmlBody(languageCode, openIdConnectRequest.GetDevice()) 
                : CreateFullHtmlBody(languageCode, openIdConnectRequest.GetDevice());
        }

        public string CreateHtmlBody()
        {
            return CreatePartialHtmlBody(DefaultLanguageCode, null);
        }

        private string CreateFullHtmlBody(string languageCode, IDevice device)
        {
            return string.Format(CultureInfo.InvariantCulture, @"<!DOCTYPE html>
            <html>
              <head>
                <title>reCAPTCHA - please prove that you are human to continue</title>
                {0}
                <script src=""https://www.google.com/recaptcha/api.js?hl={1}"" async defer></script>
              </head>
              <body>
                <form action=""?"" method=""POST"">
                  <div class=""g-recaptcha"" data-sitekey=""{2}""></div>
                  {3}
                </form>
              </body>
            </html>", CssIncludeForDevice(device), languageCode, _options.PublicKey, HtmlContentForIfNoScriptIsAllowed());
        }

        private string CreatePartialHtmlBody(string languageCode, IDevice device)
        {
            return string.Format(CultureInfo.InvariantCulture,
                @"{0}<script src=""https://www.google.com/recaptcha/api.js?hl={1}"" async defer></script>
          <div class=""g-recaptcha"" data-sitekey=""{2}""></div>{3}",
                CssIncludeForDevice(device), languageCode, _options.PublicKey, HtmlContentForIfNoScriptIsAllowed());
        }

        private string CssIncludeForDevice(IDevice device)
        {
            if (string.IsNullOrEmpty(_options.ContentServerName))
            {
                return string.Empty;
            }

            var platform = "other";
            var supportedDevices = new[] {"android", "windows", "iphone"};

            if (!string.IsNullOrEmpty(device?.DeviceType))
            {
                platform = supportedDevices.All(d => d != device.DeviceType) ? "other" : device.DeviceType;
            }

            return string.Format(CultureInfo.InvariantCulture,
                @"<link rel=""stylesheet"" type=""text/css"" media=""all"" href=""https://{0}/content/recaptcha.{1}.css""/>",
                _options.ContentServerName, platform);
        }

        private string HtmlContentForIfNoScriptIsAllowed()
        {
            if (!_options.SupportBrowsersWithoutJavaScript) return string.Empty;

            return string.Format(CultureInfo.InvariantCulture, @"<noscript>
                <div style=""width: 302px; height: 422px;"">
                    <div style=""width: 302px; height: 422px; position: relative;"">
                        <div style=""width: 302px; height: 422px; position: absolute;"">
                            <iframe src=""https://www.google.com/recaptcha/api/fallback?k={0}""
                                    frameborder=""0"" scrolling=""no""
                                    style=""width: 302px; height: 422px; border-style: none;""></iframe>
                        </div>
                    </div>
                </div>
                <div style=""width: 300px; height: 100px; border-style: none; bottom: 12px; left: 25px; margin: 0px; padding: 0px; right: 25px; background: #f9f9f9; border: 1px solid #c1c1c1; border-radius: 3px;"">
                    <textarea id=""g-recaptcha-response"" name=""g-recaptcha-response"" class=""g-recaptcha-response"" style=""width: 250px; height: 80px; border: 1px solid #c1c1c1; margin: 10px 25px; padding: 0px; resize: none;""></textarea>
                </div>
            </noscript>", _options.PublicKey);
        }
    }
}
