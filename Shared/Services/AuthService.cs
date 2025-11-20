using Shared.Models.DataModels;
using Shared.Models.WebModels;
using System.Security.Claims;

namespace Shared.Services;

public class AuthService : IAuthService
{
    private readonly HttpClient _httpClient;
    public AuthService(IHttpClientFactory httpClientFactory)
    {
        _httpClient = httpClientFactory.CreateClient("ApiClient");
    }
    
    public async Task<bool> RegisterAsync(RegisterModel registerModel)
    {
        try
        {
            var registerResult = await _httpClient.PostAsJsonAsync("api/auth/register", registerModel);
            return registerResult.IsSuccessStatusCode;
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
            var response = await _httpClient.PostAsJsonAsync("api/auth/login", loginRequest);
            return response.IsSuccessStatusCode;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }

    public Task<AuthToken?> RotateToken(string refreshTokenId)
    {
        throw new NotImplementedException();
    }

    public Task<AuthToken?> GenerateToken(string userId)
    {
        throw new NotImplementedException();
    }

    public ClaimsPrincipal? ValidateJwtToken(string token)
    {
        throw new NotImplementedException();
    }
}