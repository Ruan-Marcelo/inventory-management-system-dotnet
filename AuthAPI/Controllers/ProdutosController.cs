using AuthAPI.Data;
using AuthAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

[Authorize]
[Route("api/[controller]")]
[ApiController]
public class ProdutosController : ControllerBase
{
    private readonly ApplicationDbContext _context;

    public ProdutosController(ApplicationDbContext context)
    {
        _context = context;
    }

    // list
    [HttpGet]
    public async Task<IActionResult> Get()
    {
        var produtos = await _context.Produtos
            .Include(p => p.Categoria)
            .ToListAsync();

        return Ok(produtos);
    }

    // create
    [HttpPost]
    public async Task<IActionResult> Post([FromBody] Produto produto)
    {
        _context.Produtos.Add(produto);
        await _context.SaveChangesAsync();

        return Ok(produto);
    }
}