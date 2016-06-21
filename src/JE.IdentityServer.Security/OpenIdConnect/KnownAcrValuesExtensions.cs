using System;
using System.Collections.Generic;
using System.Linq;
using JE.IdentityServer.Security.Extensions;
using JE.IdentityServer.Security.Resources;
using Newtonsoft.Json;

namespace JE.IdentityServer.Security.OpenIdConnect
{
    public static class KnownAcrValuesExtensions
    {
        public const string RecaptchaAnswer = "x-recaptcha-answer";
        public const string Language = "language";
        public const string Sdk = "sdk";
        public const string Device = "device";
        public const string Tenant = "tenant";

        public static KnownAcrValues ToKnownAcrValues(this string raw)
        {
            if (string.IsNullOrEmpty(raw))
            {
                return new KnownAcrValues();
            }

            var valPairs = raw.Split(new[] {' '}, StringSplitOptions.RemoveEmptyEntries);
            return !valPairs.Any() ? new KnownAcrValues() : ToKnownAcrValues(valPairs);
        }

        public static KnownAcrValues ToKnownAcrValues(this IEnumerable<string> valPairs)
        {
            var acrValues = new KnownAcrValues();

            foreach (var split in valPairs.Select(pair => pair.Split(new[] {':'}, StringSplitOptions.RemoveEmptyEntries))
                                          .Where(split => split.Length == 2))
            {
                MatchAndSetKnownAcrValueFromAcrIdentifier(acrValues, split[0], split[1]);
            }

            return acrValues;
        }

        private static void MatchAndSetKnownAcrValueFromAcrIdentifier(KnownAcrValues acrValues, 
                                                                        string acrValueIdentifier, string acrValue)
        {
            switch (acrValueIdentifier)
            {
                case RecaptchaAnswer:
                    acrValues.RecaptchaResponse = acrValue;
                    break;
                case Language:
                    acrValues.Language = acrValue;
                    break;
                case Sdk:
                    acrValues.Sdk = acrValue;
                    break;
                case Device:
                    acrValues.Device = ParseDevice(acrValue);
                    break;
                case Tenant:
                    acrValues.Tenant = acrValue;
                    break;
            }
        }

        private static IDevice ParseDevice(string acrValue)
        {
            if (string.IsNullOrEmpty(acrValue))
            {
                return null;
            }

            return !acrValue.IsBase64String() 
                ? new Device(acrValue) 
                : ParseDeviceFromBase64EncodedStringValue(acrValue);
        }

        private static IDevice ParseDeviceFromBase64EncodedStringValue(string acrValue)
        {
            try
            {
                return JsonConvert.DeserializeObject<Device>(acrValue.ToStringFromBase64String());
            }
            catch (JsonException)
            {
                return null;
            }
            catch (FormatException)
            {
                return null;
            }
        }
    }
}
