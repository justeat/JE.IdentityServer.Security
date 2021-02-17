using System.Collections.Generic;
using System.Linq;
using FluentAssertions;
using JE.IdentityServer.Security.Extensions;
using NUnit.Framework;

namespace JE.IdentityServer.Security.Tests.OpenIdConnect
{
    public class AcrValuesStringExtensionTests
    {
        [TestCase(null)]
        [TestCase("")]
        [TestCase(" ")]
        [TestCase("Missing acr values")]
        [TestCase("Invalid:acr:values")]
        [TestCase("No: acr: values:")]
        public void ToAcrValues_ShouldReturnEmptyCollectionWhenNoAcrValues(string acrValues)
        {
            // Act
            var actual = acrValues.ToAcrValues();

            // Assert
            actual.Should().BeEmpty();
        }

        [Test]
        public void ToAcrValues_ShouldAcrValues()
        {
            // Arrange
            var values = new Dictionary<string, string>
            {
                ["device"] = "iOS",
                ["tenant"] = "uk",
                ["appId"] = "12345"
            };
            string acrValues = string.Join(" ", values.Select(x => $"{x.Key}:{x.Value}"));

            // Act
            var actual = acrValues.ToAcrValues();

            // Assert
            actual.Should().BeEquivalentTo(values);
        }
    }
}
