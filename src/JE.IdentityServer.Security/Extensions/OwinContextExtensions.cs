using System;
using System.IO;
using System.Linq;
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

            return new OpenIdConnectRequest(remoteIpAddress, owinContext.ResourcePath(), owinContext.Request.Headers, formAsNameValueCollection);
        }

        public static string ResourcePath(this IOwinContext owinContext)
        {
            if (owinContext == null)
            {
                throw new ArgumentNullException(nameof(owinContext));
            }

            var path = "/";

            if (owinContext.Request.PathBase.HasValue && !string.IsNullOrEmpty(owinContext.Request.PathBase.Value))
            {
                path = owinContext.Request.PathBase.Value;
            }

            if (owinContext.Request.Path.HasValue && !string.IsNullOrEmpty(owinContext.Request.Path.Value))
            {
                path = owinContext.Request.Path.Value;
            }

            return path;
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

        public static T ReadRequestBodyAsync<T>(this IOwinContext context) where T : class
        {
            try
            {
                var stream = context.Request.Body;
                if (stream == Stream.Null || !stream.CanSeek)
                {
                    return null;
                }

                var body = new StreamReader(context.Request.Body).ReadToEnd();
                if (!string.IsNullOrEmpty(body))
                {
                    return JsonConvert.DeserializeObject<T>(body);
                }
            }
            catch (JsonSerializationException)
            {
                // NOOP
            }

            return null;
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

        public static async Task CleanupAcrValues(this IOwinContext owinContext)
        {
            string text;

            using (var reader = new StreamReader(owinContext.Request.Body))
            {
                text = await reader.ReadToEndAsync();
            }

            var start = text.IndexOf("x-recaptcha-answer");

            if (start > 0)
            {
                // Don't trim the &, but trim "%20" "+" or newlines - OR just trim to the end
                var possibleEndings = new[]
                {
                    text.IndexOfAny(new[] { @"\n", "%20", "+" }, start) + 1,
                    text.IndexOf("&", start),
                    text.Length
                };

                var end = possibleEndings.Where(e => e > 0).Min();

                text = text.Remove(start, end - start);
            }

            var replacement = new MemoryStream();

            using (var writer = new StreamWriter(replacement, System.Text.Encoding.UTF8, text.Length, leaveOpen: true))
            {
                await writer.WriteAsync(text);
            }

            owinContext.Request.Body = replacement;

            // hack to prevent caching of an internalized type from Katana in environment
            owinContext.Environment.Remove("Microsoft.Owin.Form#collection");

            owinContext.Request.Body.Seek(0L, SeekOrigin.Begin);
        }
    }
}
