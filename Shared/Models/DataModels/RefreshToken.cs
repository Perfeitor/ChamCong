namespace Shared.Models.DataModels;

[Table("RefreshToken")]
public class RefreshToken
{
    /// <summary>
    /// Token này là ULID để đảm bảo tính duy nhất và có thể sắp xếp theo thời gian
    /// </summary>
    public string Token { get; private set; } = null!;

    /// <summary>
    /// Id người sở hữu token.
    /// </summary>
    public string UserId { get; private set; } = null!;

    /// <summary>
    /// Thời điểm token hiện tại hết hạn hay thời gian tối đa mà người dùng không hoạt động mà không bị đăng xuất.
    /// </summary>
    public DateTimeOffset CurrentExpiresAt { get; private set; }

    /// <summary>
    /// Thời gian sống tối đa của seassion (lifetime expiration).
    /// </summary>
    public DateTimeOffset LifetimeExpiresAt { get; private set; }

    /// <summary>
    /// Thời điểm token được tạo.
    /// </summary>
    public DateTimeOffset CreatedAt { get; private set; }

    /// <summary>
    /// Địa chỉ IP dùng để tạo token.
    /// </summary>
    public string? CreatedByIp { get; private set; }
    
    /// <summary>
    /// Định danh thiết bị (nếu có)
    /// </summary>
    public string? DeviceId { get; private set; }

    /// <summary>
    /// Thời điểm token bị thu hồi.
    /// </summary>
    public DateTimeOffset? RevokedAt { get; private set; }

    /// <summary>
    /// IP thực hiện thu hồi token.
    /// </summary>
    public string? RevokedByIp { get; private set; }

    /// <summary>
    /// Token thay thế.
    /// </summary>
    public string? ReplacedByToken { get; private set; }

    /// <summary>
    /// Lý do thu hồi (revocation reason).
    /// </summary>
    public string? RevocationReason { get; private set; }

    /// <summary>
    /// Token đã bị thu hồi hay chưa.
    /// </summary>
    [NotMapped]
    public bool IsRevoked => RevokedAt.HasValue;

    /// <summary>
    /// Token đã hết hạn hay chưa.
    /// </summary>
    [NotMapped]
    public bool IsExpired => DateTimeOffset.UtcNow >= LifetimeExpiresAt;

    /// <summary>
    /// Token không còn hợp lệ (hết hạn hoặc thu hồi).
    /// </summary>
    [NotMapped]
    public bool IsInactive => IsExpired || IsRevoked;
    
    private RefreshToken() { }
    
    public RefreshToken(
        string userId,
        DateTimeOffset lifetimeExpiresAt,
        int shortExpireMinutes,
        string? createdByIp,
        string? deviceId)
    {
        Token = Ulid.NewUlid().ToString();

        UserId = userId;
        CreatedAt = DateTimeOffset.UtcNow;
        CreatedByIp = createdByIp;
        DeviceId = deviceId;

        LifetimeExpiresAt = lifetimeExpiresAt;

        var shortLimit = CreatedAt.AddMinutes(shortExpireMinutes);

        CurrentExpiresAt = shortLimit > LifetimeExpiresAt
            ? LifetimeExpiresAt
            : shortLimit;
    }

    /// <summary>
    /// Thu hồi token.
    /// </summary>
    public void Revoke(string? revokedByIp, string? reason, string? replacedByToken = null)
    {
        RevokedAt = DateTimeOffset.UtcNow;
        RevokedByIp = revokedByIp;
        RevocationReason = reason;
        ReplacedByToken = replacedByToken;
    }
}
