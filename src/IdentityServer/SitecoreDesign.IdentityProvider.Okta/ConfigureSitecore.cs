using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Sitecore.Framework.Runtime.Configuration;
using SitecoreDesign.IdentityProvider.Okta.Configuration;

namespace SitecoreDesign.IdentityProvider.Okta
{
    public class ConfigureSitecore
    {
        private readonly ILogger<ConfigureSitecore> _logger;
        private readonly AppSettings _appSettings;

        public ConfigureSitecore(ISitecoreConfiguration scConfig, ILogger<ConfigureSitecore> logger)
        {
            _logger = logger;
            _appSettings = new AppSettings();
            scConfig.GetSection(AppSettings.SectionName);
            scConfig.GetSection(AppSettings.SectionName).Bind(_appSettings.OktaIdentityProvider);
        }

        public void ConfigureServices(IServiceCollection services)
        {
            var oktaProvider = _appSettings.OktaIdentityProvider;
            if (!oktaProvider.Enabled)
                return;
            _logger.LogDebug("Configure '" + oktaProvider.DisplayName + "'. AuthenticationScheme = " + oktaProvider.AuthenticationScheme + ", ClientId = " + oktaProvider.ClientId, Array.Empty<object>());
            new AuthenticationBuilder(services).AddOpenIdConnect(oktaProvider.AuthenticationScheme, oktaProvider.DisplayName, options =>
            {
                options.SignInScheme = "idsrv.external";
                options.ClientId = oktaProvider.ClientId;
                options.ClientSecret = oktaProvider.ClientSecret;
                options.Authority = oktaProvider.Authority;
                options.CallbackPath = new PathString("/signin-idsrv");
                options.SignedOutCallbackPath = new PathString("/signout/callback");
                options.SaveTokens = true;
                options.UseTokenLifetime = false;

                var scopes = oktaProvider.Scopes.Split(new[]{','}, StringSplitOptions.RemoveEmptyEntries);
                if (scopes.Length > 0)
                {
                    foreach (var scope in scopes)
                    {
                        options.Scope.Add(scope);
                    }
                }

                options.Events.OnRedirectToIdentityProvider += context =>
                {
                    var first = context.HttpContext.User.FindFirst("idp");
                    if (string.Equals(first?.Value, oktaProvider.AuthenticationScheme, StringComparison.Ordinal))
                        context.ProtocolMessage.Prompt = "select_account";
                    return Task.CompletedTask;
                };

                // Fix for missing id_token on logout: save it in a cookie (could also put it in a claim)
                // https://github.com/IdentityServer/IdentityServer4/issues/2283

                options.Events.OnTokenResponseReceived = context =>
                {
                    context.HttpContext.Response.Cookies.Append("id_token", context.TokenEndpointResponse.IdToken, new CookieOptions { HttpOnly = true, Secure = true });
                    return Task.CompletedTask;
                };

                options.Events.OnTokenValidated = context =>
                {
                    var form = context.HttpContext.Request.Form;
                    if (form.ContainsKey("id_token"))
                        context.HttpContext.Response.Cookies.Append("id_token", form["id_token"][0], new CookieOptions { HttpOnly = true, Secure = true });
                    return Task.CompletedTask;
                };

                options.Events.OnRedirectToIdentityProviderForSignOut += context =>
                {
                    context.ProtocolMessage.IdTokenHint = context.HttpContext.Request.Cookies["id_token"];
                    return Task.CompletedTask;
                };
                options.RequireHttpsMetadata = false;
            });
        }
    }
}
