using ApiServer.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace ApiServer.Services
{
    public class UserManagerAddon
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly ApplicationDbContext _dbContext;
        public UserManagerAddon(UserManager<IdentityUser> userManager, ApplicationDbContext dbContext)
        {
            _userManager = userManager;
            _dbContext = dbContext;
        }

        public async Task<IdentityUser?> FindUserByPhoneOrUsernameOrIdAsync(string searchValue)
        {
            IdentityUser? user;
            user = await _userManager.FindByIdAsync(searchValue);
            if (user != null)
                return user;

            user = await _userManager.FindByNameAsync(searchValue);
            if (user != null)
                return user;

            user = await _dbContext.Users.FirstOrDefaultAsync(u => u.PhoneNumber == searchValue);
            return user;
        }
    }
}
