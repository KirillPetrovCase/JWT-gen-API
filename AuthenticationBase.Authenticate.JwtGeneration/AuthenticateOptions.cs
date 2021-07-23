using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace JwtGeneration
{
    public class AuthenticateOptions
    {
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public string Secret { get; set; }
        public int TokenLifeTime { get; set; }
        public SymmetricSecurityKey GetSymmetricSecurityKey => new(Encoding.ASCII.GetBytes(Secret));
    }
}