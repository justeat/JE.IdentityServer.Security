using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace JE.IdentityServer.Security.Tests.ServiceResolver
{
    internal class TextDataSource : ITextDataSource
    {
        private readonly ConcurrentDictionary<Type, ConcurrentBag<string>> _typeOperations;

        private static readonly IEnumerable<string> Texts = new List<string>
        {
            "This is a test data source",
            "Used to test Owin dependency injection",
            "Have to wait for vNext to get DI support",
            "Although this approach is backwards compatible",
            "And allows you to plug in your own container",
            "Allows injecting a factory",
            "And is thread safe"
        };

        public TextDataSource(ConcurrentDictionary<Type, ConcurrentBag<string>> typeOperations)
        {
            _typeOperations = typeOperations;
        }

        public string GetRandomText()
        {
            WriteAndAddInfo("Getting the random text");
            return Texts.ElementAt(new Random().Next(Texts.Count()));
        }

        public IEnumerable<string> GetTexts()
        {
            WriteAndAddInfo("Getting all the texts");
            return Texts;
        }

        public void Dispose()
        {
            WriteAndAddInfo("Dispose");
        }

        private void WriteAndAddInfo(string message)
        {
            _typeOperations.AddOrUpdate(GetType(),
                (type) => new ConcurrentBag<string>(new[] { message }),
                (type, bag) => { bag.Add(message); return bag; });
        }
    }
}