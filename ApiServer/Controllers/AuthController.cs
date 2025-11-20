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
    private UserManagerAddon _userManagerAddon;

    public AuthController(IAuthService authService, UserManager<IdentityUser> userManager, IConfiguration configuration, UserManagerAddon userManagerAddon)
    {
        _authService = authService;
        _userManager = userManager;
        _configuration = configuration;
        _userManagerAddon = userManagerAddon;
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
                var user = await _userManagerAddon.FindUserByPhoneOrUsernameOrIdAsync(loginRequest.Username);
                if (user == null)
                {
                    return BadRequest();
                }
                var token = await _authService.GenerateToken(user.Id);
                if (token?.AccessToken == null || token?.RefreshToken == null)
                {
                    return BadRequest();
                }
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

    [HttpGet("refresh-token")]
    public async Task<IActionResult> RefreshToken()
    {
        try
        {
            var accessToken = Request.Cookies["access_token"];
            if (accessToken == null)
            {
                return Unauthorized("No access token provided");
            }
            if (_authService.ValidateJwtToken(accessToken) != null)
            {
                return BadRequest("Access token is still valid");
            }

            var refreshToken = Request.Cookies["refresh_token"];
            if (string.IsNullOrWhiteSpace(refreshToken))
            {
                return Unauthorized("No refresh token provided");
            }
            
            var newToken = await _authService.RotateToken(refreshToken);
            if (newToken == null)
            {
                return BadRequest();
            }

            var domain = _configuration.GetValue<string>("Jwt:Domain");
            var refreshTokenExpriresTime = DateTimeOffset.UtcNow.AddMinutes(_configuration.GetValue<int>("Jwt:RefreshTokenShortExpireMinutes"));
            var accessTokenExpriresTime = DateTimeOffset.UtcNow.AddMinutes(_configuration.GetValue<int>("Jwt:AccessTokenExpireMinutes"));

            Response.Cookies.Append("access_token", newToken.AccessToken, new CookieOptions
            {
                HttpOnly = true,
                Domain = domain,
                Secure = true,
                Expires = accessTokenExpriresTime,
                SameSite = SameSiteMode.None
            });

            Response.Cookies.Append("refresh_token", newToken.RefreshToken.Token, new CookieOptions
            {
                HttpOnly = true,
                Domain = domain,
                Secure = true,
                Expires = refreshTokenExpriresTime,
                SameSite = SameSiteMode.Lax
            });

            return Ok();
        }
        catch (Exception e)
        {
            await Console.Error.WriteLineAsync(e.Message);
            return StatusCode(500, e.Message);
        }
    }
}