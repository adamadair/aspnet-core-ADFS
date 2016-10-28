using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;
using System.Collections.Generic;
using Microsoft.AspNetCore.WebUtilities;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Net.Security;

namespace ADFS_OAuth_Sample
{
    public class Startup
    {
        public Startup(IHostingEnvironment env)
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true)
                .AddEnvironmentVariables();

            Configuration = builder.Build();
        }

        public IConfigurationRoot Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // Add framework services.
            services.AddMvc();

            // These policies demonstrate how to create policies to restrict access to controllers/actions based on role.
            // To use these policies on a controller/action, simply add the [Authorize("RequireEmployeeRole")] to the controller or action.
            services.AddAuthorization(options =>
            {
                options.AddPolicy("RequireAdministratorRole", policy => policy.RequireClaim(ClaimTypes.Role, "Administrator"));
                options.AddPolicy("RequireEmployeeRole", policy => policy.RequireClaim(ClaimTypes.Role, "Employeee"));
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole(Configuration.GetSection("Logging"));
            loggerFactory.AddDebug();

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseBrowserLink();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseStaticFiles();

            var options = new OAuthOptions();
            options.AutomaticChallenge = true;
            options.AuthenticationScheme = "ADFS";
            options.ClientId = Configuration["ADFS:ClientId"];
            options.ClientSecret = "ADFS 3.0 does not support confidential client, but OAuth middleware requires it";
            options.CallbackPath = new PathString("/signin-adfs");
            options.Events = new OAuthEvents {
                OnRedirectToAuthorizationEndpoint = context =>
                {
                    var parameter = new Dictionary<string, string>
                    {
                        ["resource"] = Configuration["ADFS:ResourceUrl"]
                    };
                    var query = QueryHelpers.AddQueryString(context.RedirectUri, parameter);
                    context.Response.Redirect(query);
                    return Task.CompletedTask;
                },
                OnCreatingTicket = context => {
                    JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
                    JwtSecurityToken validatedToken = tokenHandler.ReadJwtToken(context.AccessToken);
                    IEnumerable<Claim> a = validatedToken.Claims;

                    foreach (var claim in a)
                    {
                        // role claim needs to be mapped to http://schemas.microsoft.com/ws/2008/06/identity/claims/role
                        // for IsInRole() to work properly
                        if (claim.Type == "role")
                        {
                            context.Identity.AddClaim(new Claim(ClaimTypes.Role, claim.Value));
                        }
                        else if (claim.Type == "unique_name")
                        {
                            // map name to Identity.Name
                            context.Identity.AddClaim(new Claim(context.Identity.NameClaimType, claim.Value));
                        }
                        else
                        {
                            // this is optional, if you want any other specific claims from Active Directory
                            // this will also include some information about the jwt token such as the issue
                            // and expire times
                            context.Identity.AddClaim(new Claim(claim.Type, claim.Value));
                        }
                    }

                    return Task.CompletedTask;
                }
            };
            options.BackchannelHttpHandler = new OAuthHttpHandler();
            options.ClaimsIssuer = Configuration["ADFS:ServerUrl"];
            options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.AuthorizationEndpoint = Configuration["ADFS:ServerUrl"] + "/adfs/oauth2/authorize/";
            options.TokenEndpoint = Configuration["ADFS:ServerUrl"] + "/adfs/oauth2/token/";

            app.UseCookieAuthentication(new CookieAuthenticationOptions());
            app.UseOAuthAuthentication(options);

            // Add external authentication middleware below. To configure them please see https://go.microsoft.com/fwlink/?LinkID=532715

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
    internal class OAuthHttpHandler : HttpClientHandler
    {
        public OAuthHttpHandler() : base()
        {
            ServerCertificateCustomValidationCallback += IsCertificateValid;
        }

        private bool IsCertificateValid(HttpRequestMessage request, X509Certificate2 certificate, X509Chain chain, SslPolicyErrors errors)
        {
            #warning This is NOT production-ready code.  This will skip ALL validation of SSL certificates processed by this handler.

            return true;
        }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken = default(CancellationToken))
        {
            return base.SendAsync(request, cancellationToken);
        }
    }
}
