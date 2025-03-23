using golf1052.atproto.net;
using Yonderfix.web.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Yonderfix.web.Helpers;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Components.Authorization;
using Yonderfix.web.Components.Account;
using Yonderfix.web.Components;
using Yonderfix.web.Data;

var builder = WebApplication.CreateBuilder(args);

// Register IHttpContextAccessor (needed to access HttpContext)
builder.Services.AddHttpContextAccessor();

// Register the CustomAuthenticationStateProvider as the app's AuthenticationStateProvider.
// This ensures that our custom provider, which manages authentication state using JWT tokens,
// is used throughout the application to track user authentication status.
builder.Services.AddScoped<AuthenticationStateProvider, CustomAuthenticationStateProvider>();

// Register AtProtoClient (from golf1052.atproto.net) using the correct type name.
builder.Services.AddSingleton<AtProtoClient>();

// Register AtprotoService using a typed client factory so that both HttpClient and AtProtoClient are provided.
// Ensure that your AtprotoService is defined ONLY in the Services folder with a constructor:
//    public AtprotoService(HttpClient httpClient, AtProtoClient client)
builder.Services.AddHttpClient<AtprotoService>()
    .AddTypedClient((httpClient, sp) =>
    {
        var atProtoClient = sp.GetRequiredService<AtProtoClient>();
        return new AtprotoService(httpClient, atProtoClient);
    });

// Load user secrets in development
if (builder.Environment.IsDevelopment())
{
    builder.Configuration.AddUserSecrets<Program>();
}

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddCascadingAuthenticationState();
builder.Services.AddScoped<IdentityUserAccessor>();
builder.Services.AddScoped<IdentityRedirectManager>();
builder.Services.AddScoped<AuthenticationStateProvider, IdentityRevalidatingAuthenticationStateProvider>();

// Create an AuthenticationBuilder so we can chain authentication registration.
var authBuilder = builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = IdentityConstants.ApplicationScheme;
    options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
});

// Add Identity cookies first
authBuilder.AddIdentityCookies();

// Add the Bluesky OAuth scheme (only once)
authBuilder.AddOAuth("Bluesky", options =>
{
    options.ClientId = builder.Configuration["Authentication:Bluesky:ClientId"]
        ?? throw new InvalidOperationException("ClientId for Bluesky is not configured.");
    options.ClientSecret = builder.Configuration["Authentication:Bluesky:ClientSecret"]
        ?? throw new InvalidOperationException("ClientSecret for Bluesky is not configured.");
    options.CallbackPath = new PathString(builder.Configuration["Authentication:Bluesky:CallbackPath"]
        ?? throw new InvalidOperationException("CallbackPath for Bluesky is not configured."));
    options.AuthorizationEndpoint = builder.Configuration["Authentication:Bluesky:AuthorizationEndpoint"]
        ?? throw new InvalidOperationException("AuthorizationEndpoint for Bluesky is not configured.");
    options.TokenEndpoint = builder.Configuration["Authentication:Bluesky:TokenEndpoint"]
        ?? throw new InvalidOperationException("TokenEndpoint for Bluesky is not configured.");

    options.SaveTokens = true;
    options.Scope.Add("read"); // Add additional scopes if required

    options.Events = new OAuthEvents
    {
        OnCreatingTicket = context =>
        {
            // Optionally, use context.AccessToken to fetch user info from Bluesky
            // and add custom claims to the identity.
            return Task.CompletedTask;
        }
    };
});

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
    ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));

builder.Services.AddDatabaseDeveloperPageExceptionFilter();

builder.Services.AddIdentityCore<ApplicationUser>(options => options.SignIn.RequireConfirmedAccount = true)
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddSignInManager()
    .AddDefaultTokenProviders();

builder.Services.AddSingleton<IEmailSender<ApplicationUser>, IdentityNoOpEmailSender>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseAntiforgery();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

// Add additional endpoints required by the Identity /Account Razor components.
app.MapAdditionalIdentityEndpoints();

app.Run();
