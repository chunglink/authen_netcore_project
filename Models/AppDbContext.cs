using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace WebApplication1.Models
{
    public class AppDbContext : IdentityDbContext<IdentityUser>
    {
		public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
		{

		}

		public virtual DbSet<UserRefreshTokens> UserRefreshToken { get; set; }
	}
}
