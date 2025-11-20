using System.ComponentModel.DataAnnotations;
using Shared.Models.DataModels;

namespace Shared.Models.WebModels;

public class RegisterModel
{
    [Required(ErrorMessage = "Tên đăng nhập là bắt buộc")]
    public string Username { get; set; } = null!;
    [Required(ErrorMessage = "Mật khẩu là bắt buộc")]
    [MinLength(6, ErrorMessage = "Mật khẩu phải có ít nhất 6 ký tự")]
    [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$", ErrorMessage = "Mật khẩu phải chứa ít nhất một chữ hoa, một chữ thường, một số và một ký tự đặc biệt")]
    public string Password { get; set; } = null!;
    [Required(ErrorMessage = "Vui lòng xác nhận mật khẩu")]
    [Compare("Password", ErrorMessage = "Mật khẩu xác nhận không khớp")]
    public string ConfirmPassword { get; set; } = null!;
}

public class LoginRequest
{
    [Required(ErrorMessage =  "Tên đăng nhập là bắt buộc")]
    public string Username { get; set; } = null!;
    [Required(ErrorMessage = "Mật khẩu là bắt buộc")]
    public string Password { get; set; } = null!;
    public bool RememberMe { get; set; }
}

public class AuthToken
{
    public string AccessToken { get; set; } = null!;
    public RefreshToken RefreshToken { get; set; } = null!;

    public AuthToken(string accessToken, RefreshToken refreshToken)
    {
        AccessToken = accessToken;
        RefreshToken = refreshToken;
    }
}