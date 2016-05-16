using System;
using System.Linq;
using System.Net;
using Microsoft.Owin;

namespace JE.IdentityServer.Security.OpenIdConnect
{
    public class OpenIdConnectRequest : IOpenIdConnectRequest
    {
        private readonly IPAddress _remoteIpAddress;
        private readonly string _path;
        private readonly IHeaderDictionary _headers;
        private readonly IFormCollection _form;

        public OpenIdConnectRequest(IPAddress remoteIpAddress, string path, IHeaderDictionary headers, IFormCollection form)
        {
            _remoteIpAddress = remoteIpAddress;
            _path = path;
            _headers = headers;
            _form = form;
        }

        public string GetUsername()
        {
            return _form.Get("username");
        }

        public IPAddress GetRemoteIpAddress()
        {
            return _remoteIpAddress;
        }

        public IPAddress GetIpAddress()
        {
            return _remoteIpAddress;
        }

        public bool Matches(IOpenIdConnectRequestOptions openIdConnectRequestOptions)
        {
            var path = openIdConnectRequestOptions.ProtectedPath;
            if (string.IsNullOrEmpty(path) || !path.Equals(_path, StringComparison.OrdinalIgnoreCase)) return false;

            return openIdConnectRequestOptions.ProtectedGrantTypes.Contains(_form.Get("grant_type"));
        }

        public bool IsExcluded(IOpenIdConnectRequestOptions options)
        {
            var username = _form.Get("username");
            return !string.IsNullOrEmpty(username) && 
                    options.ExcludedUsernameExpressions.Any(regex => regex.IsMatch(username));
        }
    }
}