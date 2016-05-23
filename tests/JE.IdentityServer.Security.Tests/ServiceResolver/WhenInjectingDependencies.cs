using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Owin.Testing;
using NUnit.Framework;

namespace JE.IdentityServer.Security.Tests.ServiceResolver
{
    // We don't have dependency injection into OWIN until v2.
    // This is an interim solution up until we move the solutions to vNext
    [SuppressMessage("ReSharper", "PossibleNullReferenceException")]
    public class WhenInjectingDependencies
    {
        [Test]
        public async Task ThenPassesDependenciesCorrectlyForEndpoint()
        {
            var startup = new Startup();
            using (var server = TestServer.Create(appBuilder => { startup.Configuration(appBuilder); }))
            {
                await server.CreateRequest("/random").GetAsync();

                ConcurrentBag<string> bag;
                startup.TypeOperations.TryGetValue(typeof(TextDataSource), out bag);

                bag.Should().HaveCount(1);
            }
        }

        [Test]
        public async Task ThenPassesDependenciesCorrectlyForndpointInParallel()
        {
            var startup = new Startup();
            using (var server = TestServer.Create(appBuilder => { startup.Configuration(appBuilder); }))
            {
                const int concurrencyRate = 10;
                await Task.WhenAll(Enumerable.Range(0, concurrencyRate).Select(i => server.CreateRequest("/random").GetAsync()));

                ConcurrentBag<string> bag;
                startup.TypeOperations.TryGetValue(typeof(TextDataSource), out bag);

                bag.Should().HaveCount(concurrencyRate);
            }
        }
    }
}