using AuthAPI.Data;
using AuthAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthAPI.Controllers
{
    [Authorize(Roles = "Admin")]
    [Route("api/[controller]")]
    [ApiController]
    public class UsuariosController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public UsuariosController(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        [HttpGet]
        public async Task<IActionResult> Get()
        {
            var usuarios = await _userManager.Users
                .OrderBy(u => u.Name)
                .Select(u => new
                {
                    u.Id,
                    u.Name,
                    u.Email,
                    u.Perfil,
                    u.Ativo,
                    u.ExpiraEm,
                    u.CriadoEm
                })
                .ToListAsync();

            return Ok(usuarios);
        }

        [HttpPut("{id}")]
        public async Task<IActionResult> Put(string id, [FromBody] UsuarioUpdateModel model)
        {
            var usuario = await _userManager.FindByIdAsync(id);

            if (usuario == null)
            {
                return NotFound("Usuário não encontrado");
            }

            var perfisPermitidos = new[] { "Admin", "Funcionario", "VeterinarioParceiro" };
            var perfil = perfisPermitidos.Contains(model.Perfil) ? model.Perfil : "Funcionario";

            usuario.Name = model.Name;
            usuario.Perfil = perfil;
            usuario.Ativo = model.Ativo;
            usuario.ExpiraEm = perfil == "VeterinarioParceiro" ? model.ExpiraEm : null;

            var result = await _userManager.UpdateAsync(usuario);

            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }

            var roles = await _userManager.GetRolesAsync(usuario);
            await _userManager.RemoveFromRolesAsync(usuario, roles);
            await _userManager.AddToRoleAsync(usuario, perfil);

            return Ok(new
            {
                usuario.Id,
                usuario.Name,
                usuario.Email,
                usuario.Perfil,
                usuario.Ativo,
                usuario.ExpiraEm
            });
        }

        [HttpPut("{id}/status")]
        public async Task<IActionResult> AlterarStatus(string id, [FromBody] UsuarioUpdateModel model)
        {
            var usuario = await _userManager.FindByIdAsync(id);

            if (usuario == null)
            {
                return NotFound("Usuário não encontrado");
            }

            usuario.Ativo = model.Ativo;
            await _userManager.UpdateAsync(usuario);

            return Ok(new { usuario.Id, usuario.Ativo });
        }
    }
}
