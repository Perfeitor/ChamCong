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
    
    public AuthController(IAuthService authService, UserManager<IdentityUser> userManager)
    {
        _authService = authService;
        _userManager = userManager;
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
                return Ok("Login successful");
            }
            else
            {
                return Unauthorized("Invalid credentials");
            }
        }
        catch (Exception e)
        {
            await Console.Error.WriteLineAsync(e.Message);
            return StatusCode(500, e.Message);
        }
    }
}