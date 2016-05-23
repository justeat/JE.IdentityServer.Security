using IdentityServer3.Core.Configuration;
using Owin;

namespace JE.IdentityServer.Security.Tests.Infrastructure
{
    public static class InMemoryIdentityServerStartup
    {
        public static void UseInMemoryIdentityServer(this IAppBuilder appBuilder)
        {
            appBuilder.Map("/identity", app =>
            {
                app.UseIdentityServer(new IdentityServerOptions
                {
                    SiteName = "Embedded IdentityServer",
                    SigningCertificate = IdentityServerConfiguration.Certificate,
                    RequireSsl = false,
                    DataProtector = new NoDataProtector(),
                    Factory = new IdentityServerServiceFactory()
                        .UseInMemoryClients(IdentityServerConfiguration.Clients)
                        .UseInMemoryScopes(IdentityServerConfiguration.Scopes)
                        .UseInMemoryUsers(IdentityServerConfiguration.Users),
                });
            });
        }
    }
}
