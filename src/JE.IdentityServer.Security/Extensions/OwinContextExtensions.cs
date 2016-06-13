using System;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using JE.IdentityServer.Security.OpenIdConnect;
using Microsoft.Owin;
using Newtonsoft.Json;

namespace JE.IdentityServer.Security.Extensions
{
    public static class OwinContextExtensions
    {
        private const string IdentityKeyPrefix = "je.identityserver:security";
        
        public static IOwinContext Set<T>(this IOwinContext owinContext, T value)
        {
            if (owinContext == null)
            {
                throw new ArgumentNullException(nameof(owinContext));
            }
            return owinContext.Set(GetKey(typeof(T)), value);
        }

        public static T Get<T>(this IOwinContext owinContext)
        {
            if (owinContext == null)
            {
                throw new ArgumentNullException(nameof(owinContext));
            }

            return owinContext.Get<T>(GetKey(typeof(T)));
        }

        public static async Task<IOpenIdConnectRequest> ToOpenIdConnectRequest(this IOwinContext owinContext)
        {
            var formAsNameValueCollection = await owinContext.ReadRequestFormAsync();

            IPAddress remoteIpAddress;
            IPAddress.TryParse(owinContext.GetRemoteClientIpAddress(), out remoteIpAddress);

            return new OpenIdConnectRequest(remoteIpAddress, owinContext.Request.Path.Value, owinContext.Request.Headers, formAsNameValueCollection);
        }

        public static async Task ReturnResponse<T>(this IOwinContext owinContext, HttpStatusCode httpStatusCode, T message)
        {
            if (owinContext == null)
            {
                throw new ArgumentNullException(nameof(owinContext));
            }

            owinContext.Response.StatusCode = (int)httpStatusCode;
            owinContext.Response.ContentType = "application/json";
            await owinContext.Response.WriteAsync(JsonConvert.SerializeObject(message));
        }

        public static async Task ReturnResponse<T>(this IOwinContext owinContext, int httpStatusCode, T message)
        {
            if (owinContext == null)
            {
                throw new ArgumentNullException(nameof(owinContext));
            }

            owinContext.Response.StatusCode = httpStatusCode;
            owinContext.Response.ContentType = "application/json";
            await owinContext.Response.WriteAsync(JsonConvert.SerializeObject(message));
        }

        public static async Task ReturnResponse<T>(this IOwinContext owinContext, HttpStatusCode httpStatusCode, T resource, string authenticateChallengeHeaderValue)
        {
            if (owinContext == null)
            {
                throw new ArgumentNullException(nameof(owinContext));
            }

            owinContext.Response.Headers["WWW-Authenticate"] = authenticateChallengeHeaderValue;
            owinContext.Response.StatusCode = (int)httpStatusCode;
            owinContext.Response.ContentType = "application/json";
            await owinContext.Response.WriteAsync(JsonConvert.SerializeObject(resource));
        }
        
        private static async Task<IFormCollection> ReadRequestFormAsync(this IOwinContext owinContext)
        {
            if (owinContext == null) throw new ArgumentNullException(nameof(owinContext));

            // hack to clear a possible cached type from Katana in environment
            owinContext.Environment.Remove("Microsoft.Owin.Form#collection");

            if (!owinContext.Request.Body.CanSeek)
            {
                var copy = new MemoryStream();
                await owinContext.Request.Body.CopyToAsync(copy);

                copy.Seek(0L, SeekOrigin.Begin);
                owinContext.Request.Body = copy;
            }

            owinContext.Request.Body.Seek(0L, SeekOrigin.Begin);

            var form = await owinContext.Request.ReadFormAsync();
            owinContext.Request.Body.Seek(0L, SeekOrigin.Begin);

            // hack to prevent caching of an internalized type from Katana in environment
            owinContext.Environment.Remove("Microsoft.Owin.Form#collection");

            return form;
        }

        private static string GetKey(Type t)
        {
            return IdentityKeyPrefix + t.AssemblyQualifiedName;
        }
    }
}
