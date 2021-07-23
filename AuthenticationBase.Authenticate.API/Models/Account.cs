using AuthenticationBase.Authenticate.API.Infrastructure.Contracts;
using System;

namespace AuthenticationBase.Authenticate.API.Models
{
    public class Account
    {
        public Guid Id { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public Role[] Roles { get; set; }
    }
}