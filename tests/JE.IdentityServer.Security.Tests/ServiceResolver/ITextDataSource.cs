using System;
using System.Collections.Generic;

namespace JE.IdentityServer.Security.Tests.ServiceResolver
{
    public interface ITextDataSource : IDisposable
    {
        string GetRandomText();
        IEnumerable<string> GetTexts();
    }
}