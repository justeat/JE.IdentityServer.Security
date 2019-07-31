using System.Threading.Tasks;

namespace JE.IdentityServer.Security.Ravelin.Services
{
    public interface IRavelinService
    {
        Task SendLoginAttempt();
    }
}
