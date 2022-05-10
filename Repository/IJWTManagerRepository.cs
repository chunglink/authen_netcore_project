using System.Security.Claims;
using WebApplication1.Models;

namespace WebApplication1.Repository
{
    public interface IJWTManagerRepository
    {
        Tokens GenerateToken(string userName);
        Tokens GenerateRefreshToken(string userName);
        ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
        Tokens Authenticate(Users users);
    }
}
