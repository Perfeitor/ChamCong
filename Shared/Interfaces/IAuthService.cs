using Shared.Models.WebModels;

namespace Shared.Interfaces;

public interface IAuthService
{
    Task<bool> LoginAsync(LoginRequest loginRequest);
    Task<bool> RegisterAsync(RegisterModel registerModel);
    Task<AuthToken> GenerateJwtToken(LoginRequest loginRequest);
}