using System.Collections.Generic;
using System.Net.Http;
using JE.IdentityServer.Security.Extensions;
using JE.IdentityServer.Security.OpenIdConnect;
using JE.IdentityServer.Security.Resources;
using Microsoft.Owin.Testing;
using Newtonsoft.Json;

namespace JE.IdentityServer.Security.Tests.Infrastructure
{
    public class NativeLoginRequestBuilder
    {
        private readonly TestServer _server;
        private string _path = "/identity/connect/token";
        private string _grantType = "password";
        private string _clientId = "web_native";
        private string _secret = "cb0da8d4-2243-4f96-9a96-d01d1c301320";
        private readonly IDictionary<string, string> _headers = new Dictionary<string, string>();
        private string _username;
        private string _password;
        private string _recaptchaAnswerAcrValue;
        private string _languageCode;
        private string _device;
        private string _tenant;
        private string _osVersion;

        public NativeLoginRequestBuilder(TestServer server)
        {
            _server = server;
        }

        public NativeLoginRequestBuilder WithPath(string path)
        {
            _path = path;
            return this;
        }

        public NativeLoginRequestBuilder WithGrantType(string grantType)
        {
            _grantType = grantType;
            return this;
        }

        public NativeLoginRequestBuilder WithClientId(string clientId)
        {
            _clientId = clientId;
            return this;
        }

        public NativeLoginRequestBuilder WithSecret(string secret)
        {
            _secret = secret;
            return this;
        }

        public NativeLoginRequestBuilder WithHttpHeaderRecaptchaResponse(string httpHeaderRecaptchaResponse)
        {
            _headers.Add("x-recaptcha-answer", httpHeaderRecaptchaResponse.ToBase64String());
            return this;
        }

        public NativeLoginRequestBuilder WithRecaptchaResponseAsAcrValue(string recaptchaAnswerAcrValue)
        {
            _recaptchaAnswerAcrValue = recaptchaAnswerAcrValue;
            return this;
        }

        public NativeLoginRequestBuilder WithUsername(string username)
        {
            _username = username;
            return this;
        }

        public NativeLoginRequestBuilder WithPassword(string password)
        {
            _password = password;
            return this;
        }

        public NativeLoginRequestBuilder WithEncodedDevice(string deviceId, string deviceType, string deviceName, string deviceToken)
        {
            var device = new Device(deviceId, deviceType, deviceType, deviceToken);
            _device = JsonConvert.SerializeObject(device).ToBase64String();

            return this;
        }

        public NativeLoginRequestBuilder WithDeviceType(string deviceType)
        {
            _device = deviceType;
            return this;
        }

        public NativeLoginRequestBuilder WithLanguageCode(string languageCode)
        {
            _languageCode = languageCode;
            return this;
        }

        public NativeLoginRequestBuilder WithTenant(string tenant)
        {
            _tenant = tenant;
            return this;
        }

        public NativeLoginRequestBuilder WithOsVersion(string osVersion)
        {
            _osVersion = osVersion;
            return this;
        }

        public RequestBuilder Build()
        {
            var builder = _server.CreateRequest(_path)
                .AddHeader("HTTP_X_FORWARDED_FOR", "192.168.1.101")
                .And(x => x.Content = CreateFormUrlEncodedContent())
                .And(x => x.Headers.Authorization =
                    new BasicAuthenticationHeaderValue(_clientId, _secret));
            
            foreach (var header in _headers)
            {
                builder.AddHeader(header.Key, header.Value);
            }

            return builder;
        }

        private FormUrlEncodedContent CreateFormUrlEncodedContent()
        {
            var formInputValues = new List<KeyValuePair<string, string>>
            {
                new KeyValuePair<string, string>("username", _username),
                new KeyValuePair<string, string>("password", _password),
                new KeyValuePair<string, string>("grant_type", _grantType),
                new KeyValuePair<string, string>("scope", "mobile_scope")
            };

            var acrValues = GetAcrValues();
            if (acrValues.Count > 0)
            {
                formInputValues.Add(new KeyValuePair<string, string>("acr_values", string.Join(" ", acrValues)));
            }

            return new FormUrlEncodedContent(formInputValues);
        }

        private List<string> GetAcrValues()
        {
            var acrValues = new List<string>();

            if (!string.IsNullOrEmpty(_recaptchaAnswerAcrValue))
            {
                acrValues.Add($"{KnownAcrValuesExtensions.RecaptchaAnswer}:{_recaptchaAnswerAcrValue}");
            }

            if (!string.IsNullOrEmpty(_languageCode))
            {
                acrValues.Add($"{KnownAcrValuesExtensions.Language}:{_languageCode}");
            }

            if (!string.IsNullOrEmpty(_device))
            {
                acrValues.Add($"{KnownAcrValuesExtensions.Device}:{_device}");
            }

            if (!string.IsNullOrEmpty(_tenant))
            {
                acrValues.Add($"{KnownAcrValuesExtensions.Tenant}:{_tenant}");
            }

            if (!string.IsNullOrEmpty(_osVersion))
            {
                acrValues.Add($"{KnownAcrValuesExtensions.OsVersion}:{_osVersion}");
            }

            return acrValues;
        }
    }

    public static class NativeLoginRequestBuilderExtensions
    {
        public static NativeLoginRequestBuilder CreateNativeLoginRequest(this TestServer server)
        {
            return new NativeLoginRequestBuilder(server);
        } 
    }
}