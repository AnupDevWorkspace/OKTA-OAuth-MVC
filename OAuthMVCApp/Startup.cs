using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using System;
using System.Configuration;
using System.Threading.Tasks;

[assembly: OwinStartup(typeof(OAuthMVCApp.Startup))]

namespace OAuthMVCApp
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            bool useOktaOAuth = bool.Parse(ConfigurationManager.AppSettings["UseOktaOAuth"]);

            if (useOktaOAuth)
            {
                ConfigureOktaOAuth(app);
            }
            else
            {
                ConfigureLocalAuthentication(app);
            }
        }

        private void ConfigureOktaOAuth(IAppBuilder app)
        {
            // Add the Cookie Authentication Middleware first
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = "Cookies", // This needs to be defined and used in OpenID Connect
                LoginPath = new PathString("/Account/Login"),
                LogoutPath = new PathString("/Account/Logout")
            });

            // Use OpenID Connect for OKTA OAuth authentication
            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                ClientId = ConfigurationManager.AppSettings["okta:ClientId"],
                Authority = ConfigurationManager.AppSettings["okta:OrgUrl"],
                RedirectUri = ConfigurationManager.AppSettings["okta:RedirectUri"],
                ClientSecret = ConfigurationManager.AppSettings["okta:ClientSecret"],
                ResponseType = "code",
                Scope = "openid profile email",
                PostLogoutRedirectUri = ConfigurationManager.AppSettings["okta:PostLogoutRedirectUri"],
                TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                {
                    ValidateIssuer = true
                },
                SignInAsAuthenticationType = "Cookies", // Ensure this is set to match the CookieAuthenticationType

                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    SecurityTokenValidated = context =>
                    {
                        // Add claims to user identity
                        var claimsIdentity = context.AuthenticationTicket.Identity;
                        claimsIdentity.AddClaim(new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Name, context.AuthenticationTicket.Identity.FindFirst("name").Value));
                        claimsIdentity.AddClaim(new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Email, context.AuthenticationTicket.Identity.FindFirst("email").Value));

                        // Reissue the authentication ticket
                        context.AuthenticationTicket = new Microsoft.Owin.Security.AuthenticationTicket(claimsIdentity, context.AuthenticationTicket.Properties);
                        return Task.CompletedTask;
                    },
                    AuthenticationFailed = context =>
                    {
                        // Handle errors during authentication
                        context.HandleResponse();
                        context.Response.Redirect("/Home/Error?message=" + context.Exception.Message);
                        return Task.FromResult(0);
                    }
                }
            });
        }

        private void ConfigureLocalAuthentication(IAppBuilder app)
        {
            // If you need to configure any custom local authentication logic, do it here.
        }
    }
}
