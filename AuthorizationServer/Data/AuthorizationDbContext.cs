using Microsoft.EntityFrameworkCore;

namespace AuthorizationServer.Data
{
    public class AuthorizationDbContext : DbContext
    {
        public AuthorizationDbContext(DbContextOptions options) : base(options)
        {
        }
    }
}