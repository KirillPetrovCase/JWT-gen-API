using AuthenticationBase.Authenticate.API.Infrastructure.Contracts;
using AuthenticationBase.Authenticate.API.Models;
using JwtGeneration;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;

namespace AuthenticationBase.Authenticate.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthentificateController : ControllerBase
    {
        private readonly IOptions<AuthenticateOptions> authenticateOptions;

        public AuthentificateController(IOptions<AuthenticateOptions> authenticateOptions)
        {
            this.authenticateOptions = authenticateOptions;
        }

        private List<Account> _accountRepository => CreateRepository();

        [Route("login")]
        [HttpPost]
        public IActionResult Login([FromBody] Login request)
        {
            var user = AuthenticateUser(request.Email, request.Password);

            if (user is not null)
            {
                var token = GenerateJWT(user);

                return Ok(new { access_token = token });
            }

            return Unauthorized();
        }

        private string GenerateJWT(Account user)
        {
            var authOptions = authenticateOptions.Value;

            var securityKey = authOptions.GetSymmetricSecurityKey;
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>() {
            new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Email, user.Email),
            new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Sub, user.Id.ToString())
            };

            foreach (var role in user.Roles)
                claims.Add(new Claim("role", role.ToString()));

            var token = new JwtSecurityToken(authOptions.Issuer,
                                             authOptions.Audience,
                                             claims,
                                             expires: DateTime.Now.AddSeconds(authOptions.TokenLifeTime),
                                             signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        #region AccountRepositorySimulation

        private Account AuthenticateUser(string email, string password)
            => _accountRepository.SingleOrDefault(acc => acc.Email == email && acc.Password == password);

        private List<Account> CreateRepository()
            => new()
            {
                new Account()
                {
                    Id = Guid.NewGuid(),
                    Email = "user@mail.ru",
                    Password = "user",
                    Roles = new Role[] { Role.User }
                },
                new Account()
                {
                    Id = Guid.NewGuid(),
                    Email = "user2@mail.ru",
                    Password = "user2",
                    Roles = new Role[] { Role.User }
                },
                new Account()
                {
                    Id = Guid.NewGuid(),
                    Email = "admin@mail.ru",
                    Password = "admin",
                    Roles = new Role[] { Role.Admin }
                }
            };

        #endregion AccountRepositorySimulation
    }
}