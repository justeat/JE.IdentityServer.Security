using System.Collections.Generic;
using System.Net.Http;
using Microsoft.Owin.Testing;

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

        public RequestBuilder Build()
        {
            var builder = _server.CreateRequest(_path)
                .And(x => x.Content = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("username", _username),
                    new KeyValuePair<string, string>("password", _password),
                    new KeyValuePair<string, string>("grant_type", _grantType),
                    new KeyValuePair<string, string>("scope", "mobile_scope")
                }))
                .And(x => x.Headers.Authorization =
                    new BasicAuthenticationHeaderValue(_clientId, _secret));
            
            foreach (var header in _headers)
            {
                builder.AddHeader(header.Key, header.Value);
            }

            return builder;
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