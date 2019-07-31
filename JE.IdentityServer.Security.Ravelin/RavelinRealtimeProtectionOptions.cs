using JE.IdentityServer.Security.Ravelin.Services;

namespace JE.IdentityServer.Security.Throttling
{
    public class RavelinRealtimeProtectionOptions
    {
        public IRavelinService RavelinService { get; set; }
        public bool Enabled { get; set; }
    }
}
