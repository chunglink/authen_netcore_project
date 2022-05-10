using System.Threading.Tasks;
using WebApplication1.Models;

namespace WebApplication1.Repository
{
    public interface IUserServiceRepository
    {
		Task<bool> IsValidUserAsync(Users users);

		UserRefreshTokens AddUserRefreshTokens(UserRefreshTokens user);

		UserRefreshTokens GetSavedRefreshTokens(string username, string refreshtoken);

		void DeleteUserRefreshTokens(string username, string refreshToken);

		int SaveCommit();
	}
}
