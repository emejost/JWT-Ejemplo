using LoginJWT.Models.Entities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace LoginJWT.Controller
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private const string USERNAME = "admin";
        private const string PASSWORD = "123456";

        [HttpGet]
        public IActionResult Get()
        {
            return Ok("AuthController is working!");
        }

        [HttpPost("login")]
        public IActionResult Login(UserLogin login, IConfiguration config)
        {
            //Verificación de las credenciales
            if (login.Username != USERNAME || login.Password != PASSWORD)
                return Unauthorized();

            //Obtención de la configuración de JWT
            var jwtConfig = config.GetSection("JwtSettings");

            //Guarda la información del usuario en el token. Los claim es un dato que se guarda dentro del token.
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, login.Username), //Sub indica quien es el usuario dueño del token
                new Claim("role", "admin"), //Indica el rol del usuario
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()) //Jti para establecer identificador unico del token
            };

            //Proporciona la seguridad al token
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtConfig["Key"]!)); //Clave definida en las configuraciones codificada en bytes y validada para tokens
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256); //Firma el key con el algoritmo HmacSha256

            //Construcción del token
            var token = new JwtSecurityToken(
                issuer: jwtConfig["Issuer"],
                audience: jwtConfig["Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(1),
                signingCredentials: creds
            );

            return Ok(new {
                token = new JwtSecurityTokenHandler().WriteToken(token)
            });
        }

        [HttpGet("perfil")]
        public IActionResult Perfil()
        {
            var username = User.FindFirst(ClaimTypes.NameIdentifier)?.Value; //Obtiene el nombre del usuario autenticado
            var role = User.FindFirst(ClaimTypes.Role)?.Value; //Obtiene el rol del usuario autenticado

            return Ok(new
            {
                Username = username,
                Role = role
            });
        }
    }
}
