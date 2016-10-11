// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using IdentityServer4;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using QuickstartIdentityServer.Authentication;

namespace QuickstartIdentityServer
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();

            // For use with CachedPropertiesDataFormat. In load-balanced scenarios 
            // you should use a persistent cache such as Redis or SQL Server.
            services.AddDistributedMemoryCache();

            // configure identity server with in-memory stores, keys, clients and scopes
            services.AddDeveloperIdentityServer()
                .AddInMemoryScopes(Config.GetScopes())
                .AddInMemoryClients(Config.GetClients())
                .AddInMemoryUsers(Config.GetUsers());
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole(LogLevel.Debug);
            app.UseDeveloperExceptionPage();

            app.UseIdentityServer();

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme,

                AutomaticAuthenticate = false,
                AutomaticChallenge = false
            });

            ///
            /// Setup Custom Data Format
            /// 
            var schemeName = "oidc";
            var dataProtectionProvider = app.ApplicationServices.GetRequiredService<IDataProtectionProvider>();
            var distributedCache = app.ApplicationServices.GetRequiredService<IDistributedCache>();

            var dataProtector = dataProtectionProvider.CreateProtector(
                typeof(OpenIdConnectMiddleware).FullName,
                typeof(string).FullName, schemeName,
                "v1");

            var dataFormat = new CachedPropertiesDataFormat(distributedCache, dataProtector);

            ///
            /// Azure AD Configuration
            /// 
            var clientId = "<Your Client ID>";
            var tenantId = "<Your Tenant ID>";

            app.UseOpenIdConnectAuthentication(new OpenIdConnectOptions
            {
                AuthenticationScheme = schemeName,
                DisplayName = "AzureAD",
                SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme,
                ClientId = clientId,
                Authority = $"https://login.microsoftonline.com/{tenantId}",
                ResponseType = OpenIdConnectResponseType.IdToken,
                StateDataFormat = dataFormat
            });

            app.UseStaticFiles();
            app.UseMvcWithDefaultRoute();
        }
    }
}