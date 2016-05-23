using System.Threading.Tasks;
using JE.IdentityServer.Security.Extensions;
using Microsoft.Owin;

namespace JE.IdentityServer.Security.Tests.ServiceResolver
{
    public class RandomTextSelectorMiddleware : OwinMiddleware
    {
        public RandomTextSelectorMiddleware(OwinMiddleware next)
            : base(next)
        {
        }

        public override async Task Invoke(IOwinContext owinContext)
        {
            var textDataSource = owinContext.Get<ITextDataSource>();
            if (owinContext.Request.Path == new PathString("/random"))
            {
                await owinContext.Response.WriteAsync(textDataSource.GetRandomText());
            }
            else
            {
                owinContext.Response.Headers.Add("X-Random-Sentence", new[] { textDataSource.GetRandomText() });
                await Next.Invoke(owinContext);
            }
        }
    }
}