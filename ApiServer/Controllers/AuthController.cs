using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Shared.Models.WebModels;

namespace ApiServer.Controllers;

[Controller]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private IAuthService _authService;
    private UserManager<IdentityUser> _userManager;
    private IConfiguration _configuration;
    
    public AuthController(IAuthService authService, UserManager<IdentityUser> userManager, IConfiguration configuration)
    {
        _authService = authService;
        _userManager = userManager;
        _configuration = configuration;
    }
    
    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterModel model)
    {
        try
        {
            var registerResult = await _authService.RegisterAsync(model);
            return Ok(registerResult);
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }
    
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest loginRequest)
    {
        try
        {
            var result = await _authService.LoginAsync(loginRequest);
            if (result)
            {
                var token = await _authService.GenerateJwtToken(loginRequest);
                var domain = _configuration.GetValue<string>("Jwt:Domain");
                var refreshTokenExpriresTime = loginRequest.RememberMe ? token.RefreshToken.LifetimeExpiresAt : (DateTimeOffset?)null;
                var accessTokenExpriresTime = loginRequest.RememberMe ? token.RefreshToken.CreatedAt.AddMinutes(_configuration.GetValue<int>("AccessTokenExpireMinutes")) : (DateTimeOffset?)null;
                Response.Cookies.Append("access_token", token.AccessToken, new CookieOptions
                {
                    HttpOnly = true,
                    Domain = domain,
                    Secure = true,
                    Expires = accessTokenExpriresTime,
                    SameSite = SameSiteMode.None
                });
                Response.Cookies.Append("refresh_token", token.RefreshToken.Token, new CookieOptions
                {
                    HttpOnly = true,
                    Domain = domain,
                    Secure = true,
                    Expires = refreshTokenExpriresTime,
                    SameSite = SameSiteMode.Lax
                });
                return Ok();
            }
            else
            {
                return Unauthorized("Invalid login information");
            }
        }
        catch (Exception e)
        {
            await Console.Error.WriteLineAsync(e.Message);
            return StatusCode(500, e.Message);
        }
    }
}