using ExternalAuth.Data;
using ExternalAuth.Models;
using IdentityServer4;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Serilog;

namespace ExternalAuth
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
            services.AddControllersWithViews();

            services.AddDbContextPool<ApplicationDbContext>(options =>
                options.UseSqlite(Configuration.GetConnectionString("DefaultConnection")));

            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            #region IdentityServer register
            var builder = services.AddIdentityServer(options =>
            {
                options.Events.RaiseErrorEvents = true;
                options.Events.RaiseInformationEvents = true;
                options.Events.RaiseFailureEvents = true;
                options.Events.RaiseSuccessEvents = true;
            })
                    .AddInMemoryIdentityResources(Config.GetIdentityResources)
                    .AddInMemoryApiScopes(Config.GetApiScopes)
                    .AddInMemoryClients(Config.GetClients)
                    .AddAspNetIdentity<ApplicationUser>()
                    .AddDeveloperSigningCredential();
            #endregion

            #region Authentication with Google and Facebook
            services.AddAuthentication()
                .AddGoogle("Google", options =>
                {
                    var googleAuth = Configuration.GetSection("Authentication:Google");

                    options.ClientId = "790733433170-5t3cbu5h7lhuf298apb4r7ergv1ab482.apps.googleusercontent.com";
                    options.ClientSecret = "SfooN6v9E71b08Ksi6H3NCpu";
                    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                })
                .AddFacebook("Facebook", options =>
                {
                    options.ClientId = "450591682348790";
                    options.ClientSecret = "d09d167b66e7e1edde505143aff58190";
                    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                });
            #endregion
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, ILoggerFactory loggerFactory)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }


            #region write log to file
            var serilog = new LoggerConfiguration()
                .MinimumLevel.Verbose()
                .Enrich.FromLogContext()
                .WriteTo.File(@"authserver_log.txt");

            loggerFactory.WithFilter(new FilterLoggerSettings
                {
                    { "IdentityServer4", LogLevel.Debug },
                    { "Microsoft", LogLevel.Warning },
                    { "System", LogLevel.Warning },
                    {"Microsoft.AspNetCore.Authentication", LogLevel.Information }
                }).AddSerilog(serilog.CreateLogger());
            #endregion


            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseIdentityServer();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
