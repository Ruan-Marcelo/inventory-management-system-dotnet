using AuthAPI.Data;
using AuthAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthAPI.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class CategoriasController : ControllerBase
    {
        private readonly ApplicationDbContext _context;

        public CategoriasController(ApplicationDbContext context)
        {
            _context = context;
        }

        [HttpGet]
        public async Task<IActionResult> Get()
        {
            var categorias = await _context.Categorias
                .Where(c => c.Ativo)
                .OrderBy(c => c.Nome)
                .ToListAsync();

            return Ok(categorias);
        }

        [HttpPost]
        [Authorize(Roles = "Admin,Funcionario")]
        public async Task<IActionResult> Post([FromBody] Categoria categoria)
        {
            if (string.IsNullOrWhiteSpace(categoria.Nome))
            {
                return BadRequest("Nome da categoria é obrigatório");
            }

            categoria.Nome = categoria.Nome.Trim();
            _context.Categorias.Add(categoria);
            await _context.SaveChangesAsync();

            return Ok(categoria);
        }

        [HttpPut("{id}")]
        [Authorize(Roles = "Admin,Funcionario")]
        public async Task<IActionResult> Put(int id, [FromBody] Categoria categoria)
        {
            var categoriaDb = await _context.Categorias.FindAsync(id);

            if (categoriaDb == null)
            {
                return NotFound("Categoria não encontrada");
            }

            if (string.IsNullOrWhiteSpace(categoria.Nome))
            {
                return BadRequest("Nome da categoria é obrigatório");
            }

            categoriaDb.Nome = categoria.Nome.Trim();
            categoriaDb.Descricao = categoria.Descricao;
            categoriaDb.Ativo = categoria.Ativo;

            await _context.SaveChangesAsync();

            return Ok(categoriaDb);
        }

        [HttpDelete("{id}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> Delete(int id)
        {
            var categoria = await _context.Categorias.FindAsync(id);

            if (categoria == null)
            {
                return NotFound("Categoria não encontrada");
            }

            categoria.Ativo = false;
            await _context.SaveChangesAsync();

            return Ok(new { mensagem = "Categoria inativada" });
        }
    }
}
