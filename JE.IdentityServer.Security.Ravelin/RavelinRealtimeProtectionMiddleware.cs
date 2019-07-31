using System.Threading.Tasks;
using Microsoft.Owin;

namespace JE.IdentityServer.Security.Throttling
{
    public class RavelinRealtimeProtection : OwinMiddleware
    {
        public RavelinRealtimeProtection(OwinMiddleware next) : base(next)
        {
        }

        public override Task Invoke(IOwinContext context)
        {
            // Need to figure out if this is called during login.

            throw new System.NotImplementedException();
        }
    }
}
