using ApiServer.Data;
using Microsoft.AspNetCore.Identity;
using Shared.Models.WebModels;

namespace ApiServer.Services;

public class AuthService : IAuthService
{
    private readonly ApplicationDbContext _dbContext;
    private readonly UserManager<IdentityUser> _userManager;
    
    public AuthService(ApplicationDbContext dbContext, UserManager<IdentityUser> userManager)
    {
        _dbContext = dbContext;
        _userManager = userManager;
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
        try
        {
            if (string.IsNullOrWhiteSpace(loginRequest.Username) || string.IsNullOrWhiteSpace(loginRequest.Password))
            {
                return false;
            }
            await  Task.Delay(500);
            return true;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }
}