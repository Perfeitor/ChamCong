using Shared.Models.DataModels;
using Shared.Models.WebModels;
using System.Security.Claims;

namespace Shared.Interfaces;

public interface IAuthService
{
    Task<bool> LoginAsync(LoginRequest loginRequest);
    Task<bool> RegisterAsync(RegisterModel registerModel);
    Task<AuthToken?> GenerateToken(string userId);
    Task<AuthToken?> RotateToken(string refreshTokenId);
    ClaimsPrincipal? ValidateJwtToken(string token);
}