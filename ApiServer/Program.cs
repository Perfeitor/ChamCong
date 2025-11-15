using ApiServer.Data;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();
builder.Services.AddEntityFrameworkNpgsql();

var webdbConnectionString = builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddEntityFrameworkNpgsql().AddDbContext<ApplicationDbContext>(options =>
        options.UseNpgsql(webdbConnectionString));

builder.Services.AddIdentity<IdentityUser, IdentityRole>(options =>
    {
        options.Password.RequireDigit = true;
        options.Password.RequireLowercase = true;
        options.Password.RequireNonAlphanumeric = true;
        options.Password.RequireUppercase = true;
        options.Password.RequiredLength = 6;
        options.User.RequireUniqueEmail = false;
        options.SignIn.RequireConfirmedEmail = false;
    })
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"] ?? "FallbackSecretKey12345")),
        ValidAlgorithms = [SecurityAlgorithms.HmacSha512]
    }; 
});

builder.Services.AddScoped<IAuthService, AuthService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.UseSwagger();
    app.UseSwaggerUI();
}
else
{
    var apiSecurity = new HeaderPolicyCollection()
        .AddFrameOptionsDeny()                           // X-Frame-Options: DENY
        .AddContentTypeOptionsNoSniff()                  // X-Content-Type-Options: nosniff
        .AddReferrerPolicyNoReferrer()                   // Referrer-Policy: no-referrer
        .AddStrictTransportSecurityMaxAgeIncludeSubDomains() // HSTS 1 năm
        .RemoveServerHeader()                            // Ẩn Server: Kestrel
        .AddCrossOriginOpenerPolicy(x => x.SameOrigin()) // COOP
        .AddCrossOriginEmbedderPolicy(x => x.RequireCorp()) // COEP
        .AddCrossOriginResourcePolicy(x => x.SameOrigin()); // CORP
    app.UseSecurityHeaders(apiSecurity);
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();