using Microsoft.AspNetCore.Identity;

namespace ExternalAuth.Data
{
    public class ApplicationUser : IdentityUser
    {
        public string DisplayName { get; set; }
    }
}
