using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using WebApplication1.Models;
using WebApplication1.Repository;

namespace WebApplication1
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
			services.AddCors(options =>
			{
				options.AddPolicy("AllowSpecificOrigin",
					builder => builder.WithOrigins("http://localhost:3000")
					.AllowAnyHeader()
					.AllowAnyMethod()
					.AllowCredentials()
					);
			});
			services.AddDbContext<AppDbContext>(options => options.UseSqlServer(Configuration.GetConnectionString("SqlServerDbCon")));

			services.AddIdentity<IdentityUser, IdentityRole>(options => {
				options.Password.RequireUppercase = true; // on production add more secured options
				options.Password.RequireDigit = true;
				options.SignIn.RequireConfirmedEmail = true;
			}).AddEntityFrameworkStores<AppDbContext>().AddDefaultTokenProviders();

			services.AddAuthentication(x => {
				x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
				x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
			}).AddJwtBearer(o => {
				var Key = Encoding.UTF8.GetBytes(Configuration["JWT:Key"]);
				o.SaveToken = true;
				o.TokenValidationParameters = new TokenValidationParameters
				{
					ValidateIssuer = false, // on production make it true
					ValidateAudience = false, // on production make it true
					ValidateLifetime = true,
					ValidateIssuerSigningKey = true,
					ValidIssuer = Configuration["JWT:Issuer"],
					ValidAudience = Configuration["JWT:Audience"],
					IssuerSigningKey = new SymmetricSecurityKey(Key),
					ClockSkew = TimeSpan.Zero
				};
				o.Events = new JwtBearerEvents
				{
					OnAuthenticationFailed = context => {
						if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
						{
							context.Response.Headers.Add("IS-TOKEN-EXPIRED", "true");
						}
						return Task.CompletedTask;
					}
				};
			});

			services.AddSingleton<IJWTManagerRepository, JWTManagerRepository>();
			services.AddScoped<IUserServiceRepository, UserServiceRepository>();
			services.AddControllers();
		}

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
			app.UseCors("AllowSpecificOrigin");
			if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseHttpsRedirection();

			// your other middleware... 
			app.UseRouting();
			app.UseAuthentication(); // This need to be added before UseAuthorization()	
			app.UseAuthorization();
			app.UseEndpoints(endpoints =>
			{
				endpoints.MapControllers();
			});
		}
    }
}
