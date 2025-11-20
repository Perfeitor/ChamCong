using ApiServer.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using Shared.Models.DataModels;
using Shared.Models.WebModels;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.Tasks;
using static System.Text.Encoding;

namespace ApiServer.Services;

public class AuthService : IAuthService
{
    private readonly ApplicationDbContext _dbContext;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly IConfiguration _configuration;
    private readonly SignInManager<IdentityUser> _signInManager;

    public AuthService(ApplicationDbContext dbContext, UserManager<IdentityUser> userManager,
        IConfiguration configuration, SignInManager<IdentityUser> signInManager)
    {
        _dbContext = dbContext;
        _userManager = userManager;
        _configuration = configuration;
        _signInManager = signInManager;
    }

    public async Task<bool> RegisterAsync(RegisterModel registerModel)
    {
        try
        {
            var user = new IdentityUser
            {
                UserName = registerModel.Username,
            };
            var result = await _userManager.CreateAsync(user, registerModel.Password);
            return result.Succeeded;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }

    public async Task<bool> LoginAsync(LoginRequest loginRequest)
    {
        if (string.IsNullOrWhiteSpace(loginRequest.Username) || string.IsNullOrWhiteSpace(loginRequest.Password))
        {
            return false;
        }
        var result = await _signInManager.PasswordSignInAsync(loginRequest.Username, loginRequest.Password,
            loginRequest.RememberMe, false);
        return result.Succeeded;
    }

    private async Task<RefreshToken> CreateRefreshToken(IdentityUser user, DateTimeOffset? lifetimeExpiresAtInput = null)
    {
        var now = DateTimeOffset.UtcNow;

        DateTimeOffset lifetimeExpiresAt;
        if (lifetimeExpiresAtInput != null)
        {
            lifetimeExpiresAt = lifetimeExpiresAtInput.Value;
        }
        else
        {
            var lifetimeExpirationMinutes = _configuration.GetValue<int>("Jwt:RefreshTokenExpireMinutes");
            lifetimeExpiresAt = now.AddMinutes(lifetimeExpirationMinutes);
        }

        var refreshTokenShortExpirationMinutes = _configuration.GetValue<int>("Jwt:RefreshTokenShortExpireMinutes");
        var refreshToken = new RefreshToken(user.Id, lifetimeExpiresAt, refreshTokenShortExpirationMinutes, "", "");

        _dbContext.RefreshTokens.Add(refreshToken);
        await _dbContext.SaveChangesAsync();

        return refreshToken;
    }

    public async Task<AuthToken?> RotateToken(string refreshTokenId)
    {
        AuthToken? newToken = null;
        var lsToken = await _dbContext.RefreshTokens.Where(token => token.Token == refreshTokenId && !token.IsInactive)
            .OrderByDescending(token => token.Token)
            .ToListAsync();
        var count = lsToken.Count;
        if (count > 0)
        {
            var user = await _userManager.FindByIdAsync(lsToken[0].UserId);
            if (user == null)
            {
                return null;
            }
            var newRefreshToken = await CreateRefreshToken(user, lsToken[0].LifetimeExpiresAt);
            var newAccessToken = await GenerateJwtAccessToken(user.Id);
            newToken = new AuthToken(newAccessToken, newRefreshToken);

            if (count == 1)
            {
                _dbContext.RefreshTokens.RemoveRange(lsToken[0]);
                await _dbContext.SaveChangesAsync();
            }
            else
            {
                foreach (var token in lsToken)
                {
                    var errorId = Guid.NewGuid().ToString("N")[..10];
                    token.Revoke("System/Internal", $"Too many active Refresh Token (ErrorId: {errorId})", newRefreshToken.Token);
                    await _dbContext.SaveChangesAsync();
                }
            }
            return newToken;
        }
        return null;
    }

    public ClaimsPrincipal? ValidateJwtToken(string token)
    {
        var jwtKey = _configuration.GetValue<string>("Jwt:Key")
                     ?? throw new InvalidOperationException("Jwt:Key missing!");

        var tokenHandler = new JwtSecurityTokenHandler();
        var key = UTF8.GetBytes(jwtKey);

        try
        {
            var principal = tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = _configuration["Jwt:Issuer"],

                ValidateAudience = true,
                ValidAudience = _configuration["Jwt:Audience"],

                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),

                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            }, out _);

            return principal;
        }
        catch (SecurityTokenException ex)
        {
            Console.Error.WriteLine($"Invalid JWT Token: {ex.Message}");
            throw;
        }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine($"Invalid JWT Token: {ex.Message}");
            throw;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Unexpected error validating JWT Token: {ex.Message}");
            return null;
        }
    }

    private async Task<string> GenerateJwtAccessToken(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            throw new InvalidOperationException("User not found");
        }
        var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Name, user.UserName ?? "")
            };
        var jwtKey = _configuration.GetValue<string>("Jwt:Key")
                     ?? throw new InvalidOperationException("Jwt:Key is missing!");
        var key = new SymmetricSecurityKey(UTF8.GetBytes(jwtKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: _configuration.GetValue<string>("Jwt:Audience"),
            claims: claims,
            expires: DateTime.Now.AddMinutes(_configuration.GetValue<int>("Jwt:ExpireMinutes")),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public async Task<AuthToken?> GenerateToken(string userId)
    {
        var now = DateTimeOffset.UtcNow;
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            throw new InvalidOperationException("User not found");
        }

        var accessToken = await GenerateJwtAccessToken(user.Id);
        var refreshToken = await CreateRefreshToken(user);

        var oldRefreshTokens = await _dbContext.RefreshTokens.Where(token => token.UserId == user.Id && token.LifetimeExpiresAt > now && token.CurrentExpiresAt > now && token.RevokedAt == null).OrderByDescending(token => token.Token).ToListAsync();
        var count = oldRefreshTokens.Count;

        if (count > 0)
        {
            if (count == 1)
            {
                oldRefreshTokens[0].Revoke("System/Internal", "New login session created", refreshToken.Token);
            }
            else
            {
                foreach (var oldRefreshToken in oldRefreshTokens)
                {
                    var errorId = Guid.NewGuid().ToString("N")[..10];
                    oldRefreshToken.Revoke("System/Internal", $"Too many active Refresh Token (ErrorId: {errorId})", refreshToken.Token);
                    await _dbContext.SaveChangesAsync();
                }
            }
        }

        return new AuthToken(accessToken, refreshToken);
    }
}