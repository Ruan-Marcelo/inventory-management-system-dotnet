using AuthAPI.Data;
using AuthAPI.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.CodeDom.Compiler;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserAuthController : ControllerBase
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly string _jwtKey;
        private readonly string? _jwtIssuer;
        private readonly string? _jwtAudience;
        private readonly int _JwtExpiry;

        public UserAuthController(UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration)
        {

            _signInManager = signInManager;
            _userManager = userManager;
            _roleManager = roleManager;
            _jwtKey = configuration["Jwt:Key"] ?? throw new InvalidOperationException("Jwt:Key não configurada");
            _jwtIssuer = configuration["Jwt:Issuer"];
            _jwtAudience = configuration["Jwt:Audience"];
            _JwtExpiry = int.TryParse(configuration["Jwt:ExpiryMinutes"], out var expiry) ? expiry : 60;
        }


        [HttpPost("Register")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> Register([FromBody] RegisterModel registerModel)
        {
            try
            {
                if (registerModel == null
                    || string.IsNullOrEmpty(registerModel.Name)
                    || string.IsNullOrEmpty(registerModel.Email)
                    || string.IsNullOrEmpty(registerModel.Password))
                {
                    return BadRequest("Dados de registro inválidos");
                }

                var perfisPermitidos = new[] { "Admin", "Funcionario", "VeterinarioParceiro" };
                var perfil = perfisPermitidos.Contains(registerModel.Perfil)
                    ? registerModel.Perfil
                    : "Funcionario";

                var existingUser = await _userManager.FindByEmailAsync(registerModel.Email);
                if (existingUser != null)
                {
                    //409
                    return Conflict("E-mail já existe");
                }

                var user = new ApplicationUser
                {
                    UserName = registerModel.Email,
                    Email = registerModel.Email,
                    Name = registerModel.Name,
                    Perfil = perfil,
                    ExpiraEm = perfil == "VeterinarioParceiro" ? registerModel.ExpiraEm : null,
                    Ativo = true,
                    EmailConfirmed = true
                };

                var result = await _userManager.CreateAsync(user, registerModel.Password);

                if (!result.Succeeded)
                {
                    return BadRequest(new
                    {
                        mensagem = "Senha inválida.",
                        erros = TraduzirErrosIdentity(result.Errors)
                    });
                }

                if (!await _roleManager.RoleExistsAsync(perfil))
                {
                    await _roleManager.CreateAsync(new IdentityRole(perfil));
                }

                await _userManager.AddToRoleAsync(user, perfil);
                //200

                return Ok(new
                {
                    mensagem = "Usuário criado com sucesso",
                    user.Id,
                    user.Name,
                    user.Email,
                    user.Perfil,
                    user.ExpiraEm
                });
            }
            catch
            {
                return StatusCode(500, "Erro interno no servidor ao criar usuário");
            }

        }

        private static string[] TraduzirErrosIdentity(IEnumerable<IdentityError> errors)
        {
            return errors.Select(error => error.Code switch
            {
                "PasswordTooShort" => "A senha precisa ter pelo menos 6 caracteres.",
                "PasswordRequiresDigit" => "A senha precisa ter pelo menos 1 número.",
                "PasswordRequiresLower" => "A senha precisa ter pelo menos 1 letra minúscula.",
                "PasswordRequiresUpper" => "A senha precisa ter pelo menos 1 letra maiúscula.",
                "DuplicateUserName" => "Este e-mail já está cadastrado.",
                "DuplicateEmail" => "Este e-mail já está cadastrado.",
                "InvalidEmail" => "Informe um e-mail válido.",
                _ => error.Description
            }).ToArray();
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            var user = await _userManager.FindByEmailAsync(loginModel.Email);
            if (user == null)
            {
                //401
                return Unauthorized(new { success = false, message = "Nome de usuário ou senha inválidos" });
            }

            if (!user.Ativo || (user.ExpiraEm.HasValue && user.ExpiraEm.Value < DateTime.Now))
            {
                return Unauthorized(new { success = false, message = "Usuário inativo ou expirado" });
            }

            var result = await _signInManager.CheckPasswordSignInAsync(user, loginModel.Password, false);
            if (!result.Succeeded)
            {
                //401
                return Unauthorized(new { success = false, message = "Nome de usuário ou senha inválidos" });
            }

            //200
            var token = await GeneratedJwtToken(user);
            return Ok(new
            {
                success = true,
                token,
                usuario = new
                {
                    user.Id,
                    user.Name,
                    user.Email,
                    user.Perfil,
                    user.ExpiraEm
                }
            });
        }

        [HttpPost("Logout")]
        public async Task<IActionResult> Logout()
        {
            //200 de prima baby
            await _signInManager.SignOutAsync();
            return Ok("Usuário desconectado com sucesso.");
        }
        private async Task<string> GeneratedJwtToken(ApplicationUser user)
        {
            var roles = await _userManager.GetRolesAsync(user);

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email ?? string.Empty),
                new Claim(ClaimTypes.Email, user.Email ?? string.Empty),
                new Claim("Name", user.Name),
                new Claim("Perfil", user.Perfil),
                new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString())
            };

            claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);//sigilo d token e segurança

            var token = new JwtSecurityToken(
                //issuer: _jwtIssuer,
                //audience: _jwtAudience,
                claims: claims,
                expires: DateTime.Now.AddMinutes(_JwtExpiry),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

    }
}

//Ruan se der erro 405 e vc não lembrar de colocar o [HttpPost] ou [HttpGet] ou outro verbo http,
//é pq vc esqueceu de colocar o verbo http no método do controller, ai ele não sabe qual verbo usar e da erro 405, ai é só colocar o verbo http que ele vai funcionar (presta atenção ruanzito lindo).
