using FluentAssertions;
using JE.IdentityServer.Security.Extensions;
using JE.IdentityServer.Security.OpenIdConnect;
using JE.IdentityServer.Security.Resources;
using Newtonsoft.Json;
using NUnit.Framework;

namespace JE.IdentityServer.Security.Tests.Extensions
{
    public class ParsingKnownAcrValues
    {
        [Test]
        public void ParsingAcrValues_WithNoneSet_ShouldReturnUnsetValues()
        {
            var expectedAcrValues = new KnownAcrValues();
            var acrValues = string.Empty.ToKnownAcrValues();
            acrValues.ShouldBeEquivalentTo(expectedAcrValues);
        }

        [Test]
        public void ParsingAcrValues_WithNull_ShouldReturnUnsetValues()
        {
            var expectedAcrValues = new KnownAcrValues();
            var acrValues = ((string) null).ToKnownAcrValues();
            acrValues.ShouldBeEquivalentTo(expectedAcrValues);
        }

        [Test]
        public void ParsingAcrValues_WithSdkSet_ShouldReturnExpectedOsVersionValue()
        {
            var expectedAcrValues = new KnownAcrValues { OsVersion = "SDK1.0" };
            var acrValues = "sdk:SDK1.0".ToKnownAcrValues();
            acrValues.ShouldBeEquivalentTo(expectedAcrValues);
        }

        [Test]
        public void ParsingAcrValues_WithOsVersionSet_ShouldReturnExpectedOsVersionValue()
        {
            var expectedAcrValues = new KnownAcrValues { OsVersion = "SDK1.0" };
            var acrValues = "osversion:SDK1.0".ToKnownAcrValues();
            acrValues.ShouldBeEquivalentTo(expectedAcrValues);
        }

        [Test]
        public void ParsingAcrValues_WithLanguageSet_ShouldReturnExpectedLanguageValue()
        {
            var expectedAcrValues = new KnownAcrValues { Language = "es-ES" };
            var acrValues = "language:es-ES".ToKnownAcrValues();
            acrValues.ShouldBeEquivalentTo(expectedAcrValues);
        }

        [Test]
        public void ParsingAcrValues_WithRecaptchaResponseSet_ShouldReturnExpectedRecaptchaResponse()
        {
            var expectedAcrValues = new KnownAcrValues { RecaptchaResponse = "SomeRecaptchaResponse" };
            var acrValues = "x-recaptcha-answer:SomeRecaptchaResponse".ToKnownAcrValues();
            acrValues.ShouldBeEquivalentTo(expectedAcrValues);
        }

        [Test]
        public void ParsingAcrValues_WithTenantSet_ShouldReturnExpectedTenant()
        {
            var expectedAcrValues = new KnownAcrValues { Tenant = "es" };
            var acrValues = "tenant:es".ToKnownAcrValues();
            acrValues.ShouldBeEquivalentTo(expectedAcrValues);
        }

        [Test]
        public void ParsingAcrValues_WithNonEncodedDeviceSet_ShouldReturnExpectedDevice()
        {
            var expectedAcrValues = new KnownAcrValues { Device = new Device("all") };
            var acrValues = "device:all".ToKnownAcrValues();
            acrValues.ShouldBeEquivalentTo(expectedAcrValues);
        }

        [Test]
        public void ParsingAcrValues_WithEncodedDeviceSet_ShouldReturnExpectedDevice()
        {
            var device = new Device("deviceId", "deviceType", "deviceName", "deviceToken");
            var encodedDeviceString = JsonConvert.SerializeObject(device).ToBase64String();

            var expectedAcrValues = new KnownAcrValues { Device = new Device("deviceId", "deviceType", "deviceName", "deviceToken") };
            var acrValues = $"device:{encodedDeviceString}".ToKnownAcrValues();
            acrValues.ShouldBeEquivalentTo(expectedAcrValues);
        }
    }
}
