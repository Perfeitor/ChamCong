using MudBlazor.Services;
using ProductionLabor.WebUI.Components;
using Shared.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddMudServices();

var baseUrl = builder.Configuration["BaseUrl"];
if (baseUrl == null)
    throw new InvalidOperationException("BaseUrl configuration is missing.");
builder.Services.AddTransient<AutoRefreshTokenHandler>();
builder.Services.AddHttpClient("ApiClient", client =>
    {
        client.BaseAddress = new Uri(baseUrl);
    })
    .AddHttpMessageHandler<AutoRefreshTokenHandler>();
builder.Services.AddHttpClient("AuthClient", client =>
    {
        client.BaseAddress = new Uri(baseUrl);
    });


var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    var policyCollectios = new HeaderPolicyCollection()
        .AddFrameOptionsDeny()
        .AddContentTypeOptionsNoSniff()
        .AddStrictTransportSecurityMaxAgeIncludeSubDomains()
        .AddReferrerPolicyOriginWhenCrossOrigin()
        .RemoveServerHeader()
        .AddContentSecurityPolicy(builder =>
        {
            builder.AddDefaultSrc().Self();
            builder.AddScriptSrc().Self();
            builder.AddObjectSrc().None();
            builder.AddFrameAncestors().None();
            builder.AddFormAction().Self();
        })
        .AddCrossOriginOpenerPolicy(x => x.SameOrigin());
    app.UseSecurityHeaders(policyCollectios);

    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();


app.UseAntiforgery();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();