using System;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace JE.IdentityServer.Security.Extensions
{
    public static class StringExtensions
    {
        public static bool IsBase64String(this string base64EncodedString)
        {
            base64EncodedString = base64EncodedString.Trim();
            return (base64EncodedString.Length % 4 == 0) && Regex.IsMatch(base64EncodedString, @"^[a-zA-Z0-9\+/]*={0,3}$", RegexOptions.None);
        }

        public static string TryToStringFromBase64String(this string base64String)
        {
            try
            {
                return string.IsNullOrEmpty(base64String)
                    ? null
                    : Encoding.UTF8.GetString(Convert.FromBase64String(base64String));
            }
            catch (FormatException)
            {
                return base64String;
            }
        }

        public static string ToStringFromBase64String(this string base64String)
        {
            try
            {
                return string.IsNullOrEmpty(base64String) 
                    ? null 
                    : Encoding.UTF8.GetString(Convert.FromBase64String(base64String));
            }
            catch (FormatException)
            {
                return null;
            }
        }

        public static string ToBase64String(this string normalString)
        {
            try
            {
                return string.IsNullOrEmpty(normalString)
                    ? null
                    : Convert.ToBase64String(Encoding.UTF8.GetBytes(normalString));
            }
            catch (FormatException)
            {
                return null;
            }
        }

        public static int IndexOfAny(this string target, string[] options, int startIndex = 0, StringComparison comparison = StringComparison.OrdinalIgnoreCase)
        {
            var values = options.Select(o => target.IndexOf(o, startIndex, comparison)).Where(i => i > 0);

            return values.Any() ? values.Min() : -1;
        }
    }
}
