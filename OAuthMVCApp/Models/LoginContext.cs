using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Web;

namespace OAuthMVCApp.Models
{
    public class LoginContext : DbContext
    {
        public DbSet<User> Users { get; set; }
    }
}