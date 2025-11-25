using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);
var jwtSettings = builder.Configuration.GetSection("JwtSettings");

builder.Services.AddControllers();
builder.Services.AddAuthentication("Bearer").AddJwtBearer("Bearer", options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true, // Validar el emisor del token
        ValidateAudience = true, // Validar el público del token. Verifica que esta destinado a nosotros
        ValidateLifetime = true, // Validar que el token no haya expirado
        ValidateIssuerSigningKey = true, // Verifica que la firma sea válida
        ValidIssuer = jwtSettings["Issuer"],
        ValidAudience = jwtSettings["Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(jwtSettings["Key"]!)
            )
    };
});

builder.Services.AddAuthorization();

var app = builder.Build();

app.MapGet("/", () => "Proyecto de prueba para autenticación con JWT");

app.MapControllers();
app.UseAuthentication();
app.UseAuthorization();

app.Run();
